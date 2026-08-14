"""NepShield FastAPI application and browser routes."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, Query, Request, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pymongo.errors import PyMongoError

from app.access_control import (
    AccessControlService,
    AccessRequestNotFound,
    AccessRequestNotPending,
    DocumentAuthorizationService,
    DocumentGovernanceNotFound,
    DocumentNotRequestable,
    DocumentStateTransitionError,
    DuplicateAccessRequest,
    InvalidAccessReason,
    InvalidPermissionExpiry,
    PermissionNotRevocable,
)

from app.auth import (
    AuthService,
    AuditService,
    CannotDisableSelfError,
    InvalidDisplayNameError,
    InvalidCredentialsError,
    InvalidUsernameError,
    WeakPasswordError,
)
from app.config import settings
from app.database import MongoDatabase
from app.dependencies import (
    get_auth_service,
    get_access_control_service,
    get_csrf_service,
    get_vault_service,
    require_role,
)
from app.models import DocumentState, Role, User
from app.repositories import (
    MongoAccessRequestRepository,
    MongoAuditRepository,
    MongoDocumentPermissionRepository,
    MongoSessionRepository,
    MongoUserRepository,
    MongoVaultRepository,
)
from app.repositories import UserAlreadyExistsError
from app.security import CsrfService, CsrfValidationError
from app.vault import (
    InvalidVaultUpload,
    VaultCipher,
    VaultConfigurationError,
    VaultDocumentNotFound,
    VaultIntegrityError,
    VaultService,
    VaultStorage,
    format_file_size,
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.filters["filesize"] = format_file_size


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Start and cleanly close shared application resources."""
    database = MongoDatabase()
    await database.connect()
    application.state.database = database
    application.state.auth_service = None
    application.state.access_control_service = None
    application.state.vault_service = None
    application.state.csrf_service = CsrfService()

    mongo_database = getattr(database, "database", None)
    if mongo_database is not None:
        users = MongoUserRepository(mongo_database)
        sessions = MongoSessionRepository(mongo_database)
        audit_repository = MongoAuditRepository(mongo_database)
        vault_repository = MongoVaultRepository(mongo_database)
        access_request_repository = MongoAccessRequestRepository(mongo_database)
        permission_repository = MongoDocumentPermissionRepository(mongo_database)
        audit_service = AuditService(audit_repository)
        authorization_service = DocumentAuthorizationService(
            vault_repository, permission_repository
        )
        application.state.access_control_service = AccessControlService(
            vault_repository,
            access_request_repository,
            permission_repository,
            users,
            audit_service,
            authorization_service,
        )
        application.state.auth_service = AuthService(
            users,
            sessions,
            audit_service,
            session_lifetime=timedelta(hours=settings.session_lifetime_hours),
        )
        try:
            vault_cipher = VaultCipher.from_base64(settings.vault_encryption_key)
            application.state.vault_service = VaultService(
                vault_repository,
                VaultStorage(settings.vault_storage_dir),
                vault_cipher,
                audit_service,
                authorization_service,
                max_file_size=settings.vault_max_file_size_bytes,
            )
        except (VaultConfigurationError, OSError):
            # Authentication and health remain available while operators configure
            # vault-specific storage and key material.
            application.state.vault_service = None
        # Keep degraded-health startup behavior when MongoDB is offline.
        try:
            await users.ensure_indexes()
            await sessions.ensure_indexes()
            await audit_repository.ensure_indexes()
            await vault_repository.ensure_indexes()
            await access_request_repository.ensure_indexes()
            await permission_repository.ensure_indexes()
        except PyMongoError:
            pass

    try:
        yield
    finally:
        await database.close()


app = FastAPI(title="NepShield", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.exception_handler(CsrfValidationError)
async def csrf_error(request: Request, exc: CsrfValidationError):
    return templates.TemplateResponse(
        request=request,
        name="csrf_error.html",
        status_code=status.HTTP_403_FORBIDDEN,
    )


def request_metadata(request: Request) -> tuple[str | None, str | None]:
    source_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return source_ip, user_agent


def landing_path(user: User) -> str:
    return "/administrator" if user.role is Role.ADMINISTRATOR else "/employee"


def parse_permission_expiry(value: str) -> datetime | None:
    """Parse browser datetime input and store it as an aware UTC datetime."""
    normalized = value.strip()
    if not normalized:
        return None
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidPermissionExpiry("Enter a valid permission expiry.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, service: AuthService = Depends(get_auth_service)):
    """Route authenticated users to their role landing page."""
    user = await service.resolve_session(
        request.cookies.get(settings.session_cookie_name)
    )
    if user is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(landing_path(user), status_code=status.HTTP_303_SEE_OTHER)


@app.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    service: AuthService = Depends(get_auth_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    user = await service.resolve_session(
        request.cookies.get(settings.session_cookie_name)
    )
    if user is not None:
        return RedirectResponse(landing_path(user), status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request=request, name="login.html", context={"csrf_token": csrf.issue()}
    )


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    service: AuthService = Depends(get_auth_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    csrf.validate(csrf_token)
    source_ip, user_agent = request_metadata(request)
    try:
        user, token = await service.login(
            username,
            password,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except InvalidCredentialsError:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "The username or password is incorrect, or the account is disabled.",
                "username": username,
                "csrf_token": csrf.issue(),
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    response = RedirectResponse(
        landing_path(user), status_code=status.HTTP_303_SEE_OTHER
    )
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=settings.session_lifetime_hours * 60 * 60,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@app.post("/logout")
async def logout(
    request: Request,
    csrf_token: str = Form(""),
    service: AuthService = Depends(get_auth_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    csrf.validate(csrf_token)
    token = request.cookies.get(settings.session_cookie_name)
    source_ip, user_agent = request_metadata(request)
    await service.logout(token, source_ip=source_ip, user_agent=user_agent)
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(
        settings.session_cookie_name,
        path="/",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/employee", response_class=HTMLResponse)
async def employee_landing(
    request: Request,
    user: User = Depends(require_role(Role.EMPLOYEE)),
    csrf: CsrfService = Depends(get_csrf_service),
):
    return templates.TemplateResponse(
        request=request,
        name="employee.html",
        context={"user": user, "csrf_token": csrf.issue()},
    )


async def render_vault_page(
    request: Request,
    service: VaultService,
    csrf: CsrfService,
    user: User,
    *,
    error: str | None = None,
    success: str | None = None,
    response_status: int = status.HTTP_200_OK,
):
    return templates.TemplateResponse(
        request=request,
        name="vault.html",
        context={
            "user": user,
            "documents": await service.list_documents(user),
            "csrf_token": csrf.issue(),
            "error": error,
            "success": success,
            "max_file_size": format_file_size(service.max_file_size),
        },
        status_code=response_status,
    )


@app.get("/employee/vault", response_class=HTMLResponse)
async def employee_vault(
    request: Request,
    success: str | None = Query(default=None),
    user: User = Depends(require_role(Role.EMPLOYEE)),
    service: VaultService = Depends(get_vault_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    message = "Document encrypted and stored successfully." if success == "uploaded" else None
    return await render_vault_page(request, service, csrf, user, success=message)


@app.post("/employee/vault", response_class=HTMLResponse)
async def upload_vault_document(
    request: Request,
    document: UploadFile | None = File(default=None),
    csrf_token: str = Form(""),
    user: User = Depends(require_role(Role.EMPLOYEE)),
    service: VaultService = Depends(get_vault_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    csrf.validate(csrf_token)
    if document is None:
        return await render_vault_page(
            request,
            service,
            csrf,
            user,
            error="Choose a document to upload.",
            response_status=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    content = bytearray()
    try:
        while chunk := await document.read(64 * 1024):
            content.extend(chunk)
            if len(content) > service.max_file_size:
                raise InvalidVaultUpload(
                    f"The file exceeds the {format_file_size(service.max_file_size)} research-build limit."
                )
        source_ip, user_agent = request_metadata(request)
        await service.upload(
            user,
            document.filename,
            document.content_type,
            bytes(content),
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except InvalidVaultUpload as exc:
        return await render_vault_page(
            request,
            service,
            csrf,
            user,
            error=str(exc),
            response_status=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except (OSError, PyMongoError):
        return await render_vault_page(
            request,
            service,
            csrf,
            user,
            error="The document could not be stored. Please try again.",
            response_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    finally:
        content.clear()
        await document.close()

    return RedirectResponse(
        "/employee/vault?success=uploaded", status_code=status.HTTP_303_SEE_OTHER
    )


@app.get("/employee/vault/{document_id}/download")
async def download_vault_document(
    request: Request,
    document_id: str,
    user: User = Depends(require_role(Role.EMPLOYEE)),
    service: VaultService = Depends(get_vault_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    source_ip, user_agent = request_metadata(request)
    try:
        document, plaintext = await service.download(
            user,
            document_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except VaultDocumentNotFound:
        return await render_vault_page(
            request,
            service,
            csrf,
            user,
            error="The requested document was not found.",
            response_status=status.HTTP_404_NOT_FOUND,
        )
    except VaultIntegrityError:
        return await render_vault_page(
            request,
            service,
            csrf,
            user,
            error="The document could not be decrypted safely. Contact an administrator.",
            response_status=status.HTTP_409_CONFLICT,
        )

    encoded_name = quote(document.original_filename, safe="")
    return Response(
        content=plaintext,
        media_type=document.media_type,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


async def render_request_access_page(
    request: Request,
    service: AccessControlService,
    csrf: CsrfService,
    user: User,
    *,
    error: str | None = None,
    success: str | None = None,
    response_status: int = status.HTTP_200_OK,
):
    return templates.TemplateResponse(
        request=request,
        name="request_access.html",
        context={
            "user": user,
            "documents": await service.list_requestable(user),
            "csrf_token": csrf.issue(),
            "error": error,
            "success": success,
        },
        status_code=response_status,
    )


@app.get("/employee/access/request", response_class=HTMLResponse)
async def request_access_page(
    request: Request,
    success: str | None = Query(default=None),
    user: User = Depends(require_role(Role.EMPLOYEE)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    message = "Access request submitted for administrator review." if success else None
    return await render_request_access_page(
        request, service, csrf, user, success=message
    )


@app.post("/employee/access/request", response_class=HTMLResponse)
async def submit_access_request(
    request: Request,
    document_id: str = Form(""),
    reason: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(require_role(Role.EMPLOYEE)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    csrf.validate(csrf_token)
    source_ip, user_agent = request_metadata(request)
    try:
        await service.submit_request(
            user,
            document_id,
            reason,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except (InvalidAccessReason, DuplicateAccessRequest) as exc:
        return await render_request_access_page(
            request,
            service,
            csrf,
            user,
            error=str(exc),
            response_status=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except DocumentNotRequestable:
        return await render_request_access_page(
            request,
            service,
            csrf,
            user,
            error="The requested document is not available for access requests.",
            response_status=status.HTTP_404_NOT_FOUND,
        )
    return RedirectResponse(
        "/employee/access/request?success=submitted",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.get("/employee/access/requests", response_class=HTMLResponse)
async def my_access_requests(
    request: Request,
    user: User = Depends(require_role(Role.EMPLOYEE)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    return templates.TemplateResponse(
        request=request,
        name="my_requests.html",
        context={
            "user": user,
            "requests": await service.list_my_requests(user),
            "csrf_token": csrf.issue(),
        },
    )


@app.get("/employee/shared", response_class=HTMLResponse)
async def shared_with_me(
    request: Request,
    user: User = Depends(require_role(Role.EMPLOYEE)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    return templates.TemplateResponse(
        request=request,
        name="shared_with_me.html",
        context={
            "user": user,
            "documents": await service.list_shared_with_me(user),
            "csrf_token": csrf.issue(),
        },
    )


@app.get("/administrator", response_class=HTMLResponse)
async def administrator_landing(
    request: Request,
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    csrf: CsrfService = Depends(get_csrf_service),
):
    return templates.TemplateResponse(
        request=request,
        name="administrator.html",
        context={"user": user, "csrf_token": csrf.issue()},
    )


async def render_governance_page(
    request: Request,
    service: AccessControlService,
    csrf: CsrfService,
    user: User,
    *,
    error: str | None = None,
    success: str | None = None,
    response_status: int = status.HTTP_200_OK,
):
    return templates.TemplateResponse(
        request=request,
        name="document_governance.html",
        context={
            "user": user,
            "documents": await service.list_governance_documents(user),
            "csrf_token": csrf.issue(),
            "error": error,
            "success": success,
        },
        status_code=response_status,
    )


@app.get("/administrator/documents", response_class=HTMLResponse)
async def administrator_documents(
    request: Request,
    success: str | None = Query(default=None),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    messages = {
        "locked": "Document locked successfully.",
        "unlocked": "Document unlocked successfully.",
    }
    return await render_governance_page(
        request, service, csrf, user, success=messages.get(success)
    )


async def change_document_state(
    request: Request,
    document_id: str,
    target_state: DocumentState,
    reason: str,
    csrf_token: str,
    user: User,
    service: AccessControlService,
    csrf: CsrfService,
):
    csrf.validate(csrf_token)
    source_ip, user_agent = request_metadata(request)
    try:
        await service.change_document_state(
            user,
            document_id,
            target_state,
            reason,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except (InvalidAccessReason, DocumentStateTransitionError) as exc:
        return await render_governance_page(
            request,
            service,
            csrf,
            user,
            error=str(exc),
            response_status=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except DocumentGovernanceNotFound:
        return await render_governance_page(
            request,
            service,
            csrf,
            user,
            error="The requested document is unavailable.",
            response_status=status.HTTP_404_NOT_FOUND,
        )
    return RedirectResponse(
        "/administrator/documents?success="
        + ("locked" if target_state is DocumentState.LOCKED else "unlocked"),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/administrator/documents/{document_id}/lock")
async def lock_document(
    request: Request,
    document_id: str,
    lock_reason: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    return await change_document_state(
        request,
        document_id,
        DocumentState.LOCKED,
        lock_reason,
        csrf_token,
        user,
        service,
        csrf,
    )


@app.post("/administrator/documents/{document_id}/unlock")
async def unlock_document(
    request: Request,
    document_id: str,
    unlock_reason: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    return await change_document_state(
        request,
        document_id,
        DocumentState.ACTIVE,
        unlock_reason,
        csrf_token,
        user,
        service,
        csrf,
    )


async def render_access_requests_page(
    request: Request,
    service: AccessControlService,
    csrf: CsrfService,
    user: User,
    *,
    error: str | None = None,
    success: str | None = None,
    response_status: int = status.HTTP_200_OK,
):
    return templates.TemplateResponse(
        request=request,
        name="access_requests.html",
        context={
            "user": user,
            "requests": await service.list_all_requests(),
            "permissions": await service.list_permissions(),
            "csrf_token": csrf.issue(),
            "error": error,
            "success": success,
        },
        status_code=response_status,
    )


@app.get("/administrator/access-requests", response_class=HTMLResponse)
async def administrator_access_requests(
    request: Request,
    success: str | None = Query(default=None),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    messages = {
        "approved": "Access request approved and permission activated.",
        "rejected": "Access request rejected.",
        "revoked": "Shared permission revoked.",
    }
    return await render_access_requests_page(
        request, service, csrf, user, success=messages.get(success)
    )


@app.post("/administrator/access-requests/{request_id}/decision")
async def decide_access_request(
    request: Request,
    request_id: str,
    decision: str = Form(""),
    decision_reason: str = Form(""),
    expires_at: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    csrf.validate(csrf_token)
    source_ip, user_agent = request_metadata(request)
    try:
        expiry = parse_permission_expiry(expires_at)
        decided = await service.decide_request(
            user,
            request_id,
            decision,
            decision_reason,
            expiry,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except (InvalidAccessReason, InvalidPermissionExpiry, AccessRequestNotPending, ValueError) as exc:
        return await render_access_requests_page(
            request,
            service,
            csrf,
            user,
            error=str(exc),
            response_status=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except (AccessRequestNotFound, DocumentNotRequestable):
        return await render_access_requests_page(
            request,
            service,
            csrf,
            user,
            error="The pending access request is no longer available.",
            response_status=status.HTTP_404_NOT_FOUND,
        )
    return RedirectResponse(
        f"/administrator/access-requests?success={decided.status.value}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/administrator/permissions/{permission_id}/revoke")
async def revoke_shared_permission(
    request: Request,
    permission_id: str,
    revocation_reason: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    service: AccessControlService = Depends(get_access_control_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    csrf.validate(csrf_token)
    source_ip, user_agent = request_metadata(request)
    try:
        await service.revoke_permission(
            user,
            permission_id,
            revocation_reason,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except InvalidAccessReason as exc:
        return await render_access_requests_page(
            request,
            service,
            csrf,
            user,
            error=str(exc),
            response_status=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except (PermissionNotRevocable, DocumentNotRequestable):
        return await render_access_requests_page(
            request,
            service,
            csrf,
            user,
            error="The active permission was not found.",
            response_status=status.HTTP_404_NOT_FOUND,
        )
    return RedirectResponse(
        "/administrator/access-requests?success=revoked",
        status_code=status.HTTP_303_SEE_OTHER,
    )


async def render_users_page(
    request: Request,
    service: AuthService,
    csrf: CsrfService,
    user: User,
    *,
    error: str | None = None,
    form_data: dict[str, str] | None = None,
    success: str | None = None,
    response_status: int = status.HTTP_200_OK,
):
    return templates.TemplateResponse(
        request=request,
        name="users.html",
        context={
            "user": user,
            "users": await service.list_users(),
            "csrf_token": csrf.issue(),
            "error": error,
            "form_data": form_data or {},
            "success": success,
        },
        status_code=response_status,
    )


@app.get("/administrator/users", response_class=HTMLResponse)
async def administrator_users(
    request: Request,
    success: str | None = Query(default=None),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    service: AuthService = Depends(get_auth_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    messages = {
        "created": "Employee account created successfully.",
        "enabled": "Account enabled successfully.",
        "disabled": "Account disabled successfully.",
    }
    return await render_users_page(request, service, csrf, user, success=messages.get(success))


@app.post("/administrator/users", response_class=HTMLResponse)
async def create_employee_account(
    request: Request,
    display_name: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    service: AuthService = Depends(get_auth_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    csrf.validate(csrf_token)
    try:
        await service.create_employee(display_name, username, password, actor=user)
    except UserAlreadyExistsError:
        error = "That username is already in use."
    except (InvalidDisplayNameError, InvalidUsernameError, WeakPasswordError) as exc:
        error = str(exc)
    else:
        return RedirectResponse(
            "/administrator/users?success=created", status_code=status.HTTP_303_SEE_OTHER
        )
    return await render_users_page(
        request,
        service,
        csrf,
        user,
        error=error,
        form_data={"display_name": display_name, "username": username},
        response_status=status.HTTP_422_UNPROCESSABLE_CONTENT,
    )


@app.post("/administrator/users/status")
async def change_account_status(
    request: Request,
    username: str = Form(""),
    enabled: bool = Form(...),
    csrf_token: str = Form(""),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
    service: AuthService = Depends(get_auth_service),
    csrf: CsrfService = Depends(get_csrf_service),
):
    csrf.validate(csrf_token)
    try:
        await service.set_user_enabled(username, enabled, actor=user)
    except CannotDisableSelfError as exc:
        return await render_users_page(
            request, service, csrf, user, error=str(exc), response_status=status.HTTP_422_UNPROCESSABLE_CONTENT
        )
    except LookupError:
        return await render_users_page(
            request, service, csrf, user, error="The requested account no longer exists.", response_status=status.HTTP_404_NOT_FOUND
        )
    message = "enabled" if enabled else "disabled"
    return RedirectResponse(
        f"/administrator/users?success={message}", status_code=status.HTTP_303_SEE_OTHER
    )


@app.get("/health")
async def health(request: Request):
    """Report application and MongoDB connectivity health."""
    database_healthy = await request.app.state.database.ping()
    payload = {
        "status": "healthy" if database_healthy else "unhealthy",
        "database": {"status": "healthy" if database_healthy else "unhealthy"},
    }

    if not database_healthy:
        return JSONResponse(status_code=503, content=payload)
    return payload
