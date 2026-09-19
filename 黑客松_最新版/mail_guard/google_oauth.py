from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx


AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify"


@dataclass
class GoogleTokens:
    access_token: str
    refresh_token: str | None
    expires_at: float


class GoogleOAuth:
    """Hackathon OAuth flow. Tokens stay in memory and vanish on restart."""

    def __init__(self) -> None:
        self.client_id = os.getenv("GOOGLE_CLIENT_ID", "")
        self.client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
        self.redirect_uri = os.getenv(
            "GOOGLE_REDIRECT_URI",
            "http://127.0.0.1:8000/auth/google/callback",
        )
        self._tokens: dict[str, GoogleTokens] = {}

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self.redirect_uri)

    def authorization_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": GMAIL_SCOPE,
            "access_type": "offline",
            "include_granted_scopes": "true",
            "prompt": "consent",
            "state": state,
        }
        return f"{AUTHORIZATION_ENDPOINT}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> GoogleTokens:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                TOKEN_ENDPOINT,
                data={
                    "code": code,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "redirect_uri": self.redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
            response.raise_for_status()
            data = response.json()
        return GoogleTokens(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_at=time.time() + int(data.get("expires_in", 3600)) - 60,
        )

    def create_session(self, tokens: GoogleTokens) -> str:
        session_id = secrets.token_urlsafe(32)
        self._tokens[session_id] = tokens
        return session_id

    async def access_token_for(self, session_id: str) -> str | None:
        tokens = self._tokens.get(session_id)
        if not tokens:
            return None
        if time.time() < tokens.expires_at:
            return tokens.access_token
        if not tokens.refresh_token:
            self._tokens.pop(session_id, None)
            return None

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                TOKEN_ENDPOINT,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": tokens.refresh_token,
                    "grant_type": "refresh_token",
                },
            )
            response.raise_for_status()
            data = response.json()
        tokens.access_token = data["access_token"]
        tokens.expires_at = time.time() + int(data.get("expires_in", 3600)) - 60
        return tokens.access_token

    def delete_session(self, session_id: str) -> None:
        self._tokens.pop(session_id, None)
