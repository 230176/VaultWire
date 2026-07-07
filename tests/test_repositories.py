"""Regression tests for safe MongoDB index initialization."""

import asyncio
from datetime import UTC, datetime

from app.repositories import (
    MongoAccessRequestRepository,
    MongoDocumentPermissionRepository,
    MongoUserRepository,
)


class IndexCollection:
    def __init__(self, indexes):
        self.indexes = indexes
        self.create_calls = []

    async def index_information(self):
        return self.indexes

    async def create_index(self, keys, **options):
        self.create_calls.append((keys, options))


def test_existing_legacy_unique_username_index_is_reused_without_creation():
    collection = IndexCollection(
        {
            "_id_": {"key": [("_id", 1)]},
            "username_1": {"key": [("username", 1)], "unique": True},
            "role_1": {"key": [("role", 1)]},
            "is_active_1": {"key": [("is_active", 1)]},
        }
    )
    repository = MongoUserRepository({"users": collection})

    asyncio.run(repository.ensure_indexes())

    assert collection.create_calls == []


def test_legacy_iso_creation_timestamp_is_normalized_for_user_page_rendering():
    user = MongoUserRepository._to_user(
        {
            "_id": "legacy-user-id",
            "username": "admin",
            "password_hash": "not-used-in-this-test",
            "role": "administrator",
            "enabled": True,
            "created_at": "2026-07-13T07:15:45.567397+00:00",
        }
    )

    assert user is not None
    assert user.created_at == datetime(2026, 7, 13, 7, 15, 45, 567397, tzinfo=UTC)


def test_access_request_index_prevents_only_duplicate_pending_relationships():
    collection = IndexCollection({})
    repository = MongoAccessRequestRepository({"access_requests": collection})

    asyncio.run(repository.ensure_indexes())

    pending_index = next(
        options
        for _, options in collection.create_calls
        if options.get("name") == "unique_pending_document_request"
    )
    assert pending_index["unique"] is True
    assert pending_index["partialFilterExpression"] == {"status": "pending"}


def test_permission_index_enforces_one_grantee_document_relationship():
    collection = IndexCollection({})
    repository = MongoDocumentPermissionRepository(
        {"document_permissions": collection}
    )

    asyncio.run(repository.ensure_indexes())

    relationship_index = next(
        (keys, options)
        for keys, options in collection.create_calls
        if options.get("name") == "unique_document_grantee_permission"
    )
    assert relationship_index[0] == [("grantee_id", 1), ("document_id", 1)]
    assert relationship_index[1]["unique"] is True
