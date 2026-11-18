from functools import lru_cache

from supabase import Client, ClientOptions, create_client

from app.config import get_settings


def new_publishable_client() -> Client:
    """A throwaway publishable-key client, so a sign-in never leaves a session on a shared client."""
    settings = get_settings()
    if not settings.supabase_publishable_key:
        raise RuntimeError("SUPABASE_PUBLISHABLE_KEY is not configured")
    return create_client(
        settings.supabase_url,
        settings.supabase_publishable_key,
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )


@lru_cache
def get_supabase() -> Client:
    settings = get_settings()
    return create_client(
        settings.supabase_url,
        settings.supabase_secret_key,
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )
