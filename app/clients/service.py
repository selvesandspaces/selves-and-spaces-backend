import re


class ClientNotFoundError(Exception):
    pass


def _escape(q: str) -> str:
    # Strip characters that are special in PostgREST's or_() filter syntax and in ILIKE.
    return re.sub(r"[,()%*_\\]", " ", q).strip()


def list_clients(db, limit: int, offset: int, status: str | None, q: str | None) -> list[dict]:
    query = db.table("clients").select("*")
    if status:
        query = query.eq("status", status)
    term = _escape(q) if q else ""
    if term:
        query = query.or_(f"name.ilike.%{term}%,email.ilike.%{term}%")
    return query.order("created_at", desc=True).order("id").range(offset, offset + limit - 1).execute().data


def get_client(db, client_id: str) -> dict:
    rows = db.table("clients").select("*").eq("id", client_id).limit(1).execute().data
    if not rows:
        raise ClientNotFoundError(client_id)
    return rows[0]
