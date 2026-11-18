import logging
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth.deps import CurrentUser, require_roles
from app.auth.roles import Role
from app.clients import service
from app.clients.schemas import ClientOut
from app.supabase_client import get_supabase

logger = logging.getLogger("audit")

admin_router = APIRouter(prefix="/admin/clients", tags=["admin-clients"])

SuperAdmin = Annotated[CurrentUser, Depends(require_roles(Role.SUPER_ADMIN))]


@admin_router.get("")
def list_clients(
    current: SuperAdmin,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    client_status: Annotated[Literal["active", "inactive"] | None, Query(alias="status")] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
) -> list[ClientOut]:
    rows = service.list_clients(get_supabase(), limit, offset, client_status, q)
    logger.info("client.list actor=%s count=%s", current.id, len(rows))
    return [ClientOut(**r) for r in rows]


@admin_router.get("/{client_id}")
def get_client(client_id: UUID, current: SuperAdmin) -> ClientOut:
    try:
        row = service.get_client(get_supabase(), str(client_id))
    except service.ClientNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found") from None
    logger.info("client.view actor=%s client=%s", current.id, client_id)
    return ClientOut(**row)
