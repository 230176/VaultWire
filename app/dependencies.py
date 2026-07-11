"""FastAPI dependencies for authenticated and role-restricted routes."""

from collections.abc import Callable

from fastapi import Cookie, Depends, HTTPException, Request, status

from app.auth import AuthService
from app.access_control import AccessControlService
from app.security import CsrfService
from app.config import settings
from app.models import Role, User
from app.vault import VaultService


def get_auth_service(request: Request) -> AuthService:
    service = getattr(request.app.state, "auth_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication storage is unavailable.",
        )
    return service


def get_csrf_service(request: Request) -> CsrfService:
    return request.app.state.csrf_service


def get_vault_service(request: Request) -> VaultService:
    service = getattr(request.app.state, "vault_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vault storage is unavailable or not configured.",
        )
    return service


def get_access_control_service(request: Request) -> AccessControlService:
    service = getattr(request.app.state, "access_control_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document access storage is unavailable.",
        )
    return service


async def get_current_user(
    service: AuthService = Depends(get_auth_service),
    session_token: str | None = Cookie(
        default=None, alias=settings.session_cookie_name
    ),
) -> User:
    user = await service.resolve_session(session_token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    return user


def require_role(role: Role) -> Callable[..., User]:
    async def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role is not role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this area.",
            )
        return user

    return dependency
