import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.auth.deps import CurrentUser, get_active_customer, require_roles
from app.auth.roles import Role
from app.config import get_settings
from app.supabase_client import get_supabase, new_publishable_client
from app.users import service
from app.users.schemas import PasswordChange, UserOut, UserUpdate

logger = logging.getLogger("audit")

router = APIRouter(prefix="/users", tags=["users"])

SuperAdmin = Annotated[CurrentUser, Depends(require_roles(Role.SUPER_ADMIN))]

Customer = Annotated[CurrentUser, Depends(get_active_customer)]

# Supabase has no "disable user" flag; a very long ban is the documented way.
DEACTIVATE_FOR = "876000h"  # ~100 years


@router.patch("/me")
def update_me(data: UserUpdate, user: Customer) -> UserOut:
    changes = data.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Send at least one field to update")
    is_super = Role.SUPER_ADMIN in user.roles
    if "email" in changes and get_settings().require_confirmed_email and not is_super:
        # The admin API would switch the login email with no verification step.
        # (The super admin is exempt: they are the operator and have no one to confirm with.)
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Change your email from the sign-in client so a confirmation is sent",
        )
    admin = get_supabase().auth.admin
    current = admin.get_user_by_id(user.id).user
    attributes: dict = {"user_metadata": {**(current.user_metadata or {}), **{k: v for k, v in changes.items() if k != "email"}}}
    if "email" in changes:
        attributes["email"] = changes["email"]
        if is_super:
            attributes["email_confirm"] = True
    updated = admin.update_user_by_id(user.id, attributes).user
    logger.info("user.update actor=%s fields=%s", user.id, ",".join(sorted(changes)))
    return UserOut.from_supabase(updated)


@router.post("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def change_my_password(data: PasswordChange, current: SuperAdmin) -> Response:
    if not get_settings().supabase_publishable_key:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Password change is not configured")
    admin = get_supabase().auth.admin
    # Fresh email, not the token's: the token's can be stale right after an email change.
    email = admin.get_user_by_id(current.id).user.email
    if not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Account has no email")
    if data.new_password == data.current_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "New password must differ from the current one")
    try:
        service.change_password(
            admin, new_publishable_client(), current.id, email, data.current_password, data.new_password,
        )
    except service.WrongPasswordError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect") from None
    logger.info("user.password_change actor=%s", current.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("")
def list_users(
    _: SuperAdmin,
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[int, Query(ge=1, le=100)] = 50,
    role: Role | None = None,
) -> list[UserOut]:
    users = service.list_users(get_supabase().auth.admin, page, per_page, role)
    return [UserOut.from_supabase(u) for u in users]


@router.get("/{user_id}")
def get_user(user_id: UUID, _: SuperAdmin) -> UserOut:
    user = get_supabase().auth.admin.get_user_by_id(str(user_id)).user
    return UserOut.from_supabase(user)


@router.post("/{user_id}/deactivate")
def deactivate_user(user_id: UUID, current: SuperAdmin) -> UserOut:
    admin = get_supabase().auth.admin
    target = admin.get_user_by_id(str(user_id)).user
    if target.id == current.id or Role.SUPER_ADMIN in service.user_roles(target):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The super admin cannot be deactivated")
    updated = admin.update_user_by_id(target.id, {"ban_duration": DEACTIVATE_FOR}).user
    logger.info("user.deactivate actor=%s target=%s", current.id, target.id)
    return UserOut.from_supabase(updated)


@router.post("/{user_id}/activate")
def activate_user(user_id: UUID, current: SuperAdmin) -> UserOut:
    admin = get_supabase().auth.admin
    updated = admin.update_user_by_id(str(user_id), {"ban_duration": "none"}).user
    logger.info("user.activate actor=%s target=%s", current.id, user_id)
    return UserOut.from_supabase(updated)
