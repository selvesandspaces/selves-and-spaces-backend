from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel


class ClientOut(BaseModel):
    id: str
    name: str
    email: str | None = None
    phone: str | None = None
    date_of_birth: date | None = None
    address: str | None = None
    therapist_name: str | None = None
    session_notes: str | None = None
    emergency_contact_name: str | None = None
    emergency_contact_phone: str | None = None
    status: Literal["active", "inactive"]
    created_at: datetime
    updated_at: datetime
