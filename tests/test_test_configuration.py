import pytest

from app.config import settings
from app.database import MongoDatabase


def test_pytest_uses_a_dedicated_database_name():
    assert settings.app_env == "testing"
    assert settings.mongodb_database == "nepshield_test"
    assert settings.mongodb_database != "nepshield"


def test_testing_environment_rejects_development_database_name():
    with pytest.raises(RuntimeError, match="Refusing to use the development MongoDB database"):
        MongoDatabase(name="nepshield")
