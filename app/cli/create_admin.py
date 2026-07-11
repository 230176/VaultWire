"""Interactively create NepShield's initial administrator account."""

import asyncio
import getpass

from pymongo.errors import PyMongoError

from app.auth import AuthService, AuditService, InvalidUsernameError, WeakPasswordError
from app.config import settings
from app.database import MongoDatabase
from app.models import Role
from app.repositories import (
    MongoAuditRepository,
    MongoSessionRepository,
    MongoUserRepository,
    UsernameIndexConfigurationError,
    UserAlreadyExistsError,
)


async def create_administrator() -> None:
    print("Create the initial NepShield administrator")
    print("Credentials are entered locally and the password is never displayed.")
    username = input("Username: ")
    password = getpass.getpass("Password (12-1024 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords did not match; no account was created.")

    database = MongoDatabase()
    await database.connect()
    try:
        users = MongoUserRepository(database.database)
        sessions = MongoSessionRepository(database.database)
        audit_repository = MongoAuditRepository(database.database)
        await users.ensure_indexes()
        await sessions.ensure_indexes()
        await audit_repository.ensure_indexes()
        service = AuthService(users, sessions, AuditService(audit_repository))
        administrator = await service.create_user(
            username, password, Role.ADMINISTRATOR
        )
    except UserAlreadyExistsError:
        raise SystemExit("That username already exists; no account was created.")
    except (InvalidUsernameError, WeakPasswordError) as error:
        raise SystemExit(str(error))
    except UsernameIndexConfigurationError as error:
        raise SystemExit(str(error))
    except PyMongoError as error:
        raise SystemExit(
            f"Could not create the administrator in {settings.mongodb_database}: {error}"
        )
    finally:
        await database.close()

    print(f"Administrator '{administrator.username}' created successfully.")


if __name__ == "__main__":
    asyncio.run(create_administrator())
