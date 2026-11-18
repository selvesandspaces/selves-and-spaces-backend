"""Unit tests for the admin therapist-client routes. Supabase is faked."""

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app

ADMIN_ID = str(uuid4())
CUSTOMER_ID = str(uuid4())
NOW = datetime.now(timezone.utc).isoformat()


class FakeQuery:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def select(self, *_):
        return self

    def eq(self, col, val):
        self.rows = [r for r in self.rows if r.get(col) == val]
        return self

    def or_(self, expr):
        self.calls.append(expr)
        return self

    def order(self, *_, **__):
        return self

    def range(self, start, end):
        self.rows = self.rows[start : end + 1]
        return self

    def limit(self, *_):
        return self

    def execute(self):
        return SimpleNamespace(data=self.rows)


def client_row(name="Asha", status="active"):
    return {"id": str(uuid4()), "name": name, "status": status, "session_notes": "notes", "created_at": NOW, "updated_at": NOW}


class FakeDB:
    def __init__(self):
        self.clients = [client_row("Asha"), client_row("Ben", "inactive")]
        self.caller = {"sub": ADMIN_ID, "app_metadata": {"roles": ["super_admin"]}}
        self.auth = self
        self.admin = self
        self.users = {
            ADMIN_ID: SimpleNamespace(app_metadata={"roles": ["super_admin"]}, banned_until=None),
            CUSTOMER_ID: SimpleNamespace(app_metadata={}, banned_until=None),
        }

    def get_claims(self, token):
        return {"claims": self.caller}

    def get_user_by_id(self, uid):
        return SimpleNamespace(user=self.users[uid])

    def table(self, name):
        assert name == "clients"
        return FakeQuery(list(self.clients))


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    for target in ("app.auth.deps.get_supabase", "app.clients.router.get_supabase"):
        monkeypatch.setattr(target, lambda: fake)
    return fake


def authed():
    return TestClient(app, headers={"Authorization": "Bearer t.t.t"})


def test_admin_lists_and_filters_clients(db):
    c = authed()
    assert [x["name"] for x in c.get("/admin/clients").json()] == ["Asha", "Ben"]
    assert [x["name"] for x in c.get("/admin/clients?status=inactive").json()] == ["Ben"]
    assert len(c.get("/admin/clients?limit=1").json()) == 1
    assert c.get("/admin/clients?limit=0").status_code == 422
    assert c.get("/admin/clients?status=bogus").status_code == 422


def test_admin_views_client_detail_and_404(db):
    c = authed()
    cid = db.clients[0]["id"]
    assert c.get(f"/admin/clients/{cid}").json()["session_notes"] == "notes"
    assert c.get(f"/admin/clients/{uuid4()}").status_code == 404


@pytest.mark.parametrize("path", ["/admin/clients", f"/admin/clients/{uuid4()}"])
def test_customer_and_anonymous_are_blocked(db, path):
    db.caller = {"sub": CUSTOMER_ID}
    assert authed().get(path).status_code == 403
    assert TestClient(app).get(path).status_code in (401, 403)
