from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints
from supabase_auth.types import User

from app.orders.schemas import ShippingAddress
from app.users.service import effective_roles, is_banned


class UserUpdate(BaseModel):
    """What a customer may change about themselves. Roles are deliberately absent (and rejected)."""

    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)] | None = None
    phone: Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^\+?[0-9][0-9 \-]{5,18}[0-9]$")] | None = None
    email: Annotated[str, StringConstraints(strip_whitespace=True, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")] | None = None
    # Replaced as a whole, not merged field by field.
    address: ShippingAddress | None = None


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    new_password: Annotated[str, StringConstraints(min_length=8, max_length=256)]


class UserOut(BaseModel):
    id: str
    email: str | None
    roles: list[str]
    created_at: datetime
    last_sign_in_at: datetime | None
    deactivated: bool
    name: str | None = None
    phone: str | None = None
    address: ShippingAddress | None = None

    @classmethod
    def from_supabase(cls, user: User) -> "UserOut":
        meta = user.user_metadata or {}
        return cls(
            id=user.id,
            email=user.email,
            roles=effective_roles(user),
            created_at=user.created_at,
            last_sign_in_at=user.last_sign_in_at,
            deactivated=is_banned(user),
            name=meta.get("name"),
            phone=meta.get("phone"),
            address=meta.get("address"),
        )
