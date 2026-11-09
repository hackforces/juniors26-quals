"""Runtime settings.

prequals rules:
- the flag comes from the environment at container start — `CTF_FLAG` only;
  no default, ever;
- `JWT_SECRET` falls back to a fresh random secret per boot when the
  environment does not provide one, so tokens never share a known key.
"""

import os
import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict


def _required_flag() -> str:
    flag = os.environ.get("CTF_FLAG")
    if not flag:
        raise RuntimeError(
            "CTF_FLAG env is required — refusing to start without a flag"
        )
    return flag


# Module-level on purpose: read from the environment exactly once, before
# pydantic-settings can interfere.
FLAG = _required_flag()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "sqlite+aiosqlite:////app/data/app.db"

    jwt_secret: str = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(48)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 120


settings = Settings()
