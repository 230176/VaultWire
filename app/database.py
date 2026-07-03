"""MongoDB connection lifecycle helpers."""

from pymongo import AsyncMongoClient
from pymongo.errors import PyMongoError

from app.config import settings


class MongoDatabase:
    """Manage the application's MongoDB client and connectivity checks."""

    def __init__(self, uri: str = settings.mongodb_uri, name: str = settings.mongodb_database):
        if settings.app_env == "testing" and name == "nepshield":
            raise RuntimeError(
                "Refusing to use the development MongoDB database while testing. "
                "Set MONGODB_DATABASE to a dedicated test database."
            )
        self._uri = uri
        self._name = name
        self.client: AsyncMongoClient | None = None
        self.database = None

    async def connect(self) -> None:
        """Create the client without failing app startup if MongoDB is offline."""
        self.client = AsyncMongoClient(self._uri, serverSelectionTimeoutMS=2_000)
        self.database = self.client[self._name]

    async def ping(self) -> bool:
        """Return whether the MongoDB server is reachable."""
        if self.client is None:
            return False

        try:
            await self.client.admin.command({"ping": 1})
        except PyMongoError:
            return False
        return True

    async def close(self) -> None:
        """Close the client and release its connection resources."""
        if self.client is not None:
            await self.client.close()
            self.client = None
            self.database = None
