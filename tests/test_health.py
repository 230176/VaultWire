from fastapi.testclient import TestClient

import app.main


class FakeDatabase:
    healthy = True

    async def connect(self):
        pass

    async def ping(self):
        return self.healthy

    async def close(self):
        pass


def test_health_reports_healthy_application_and_database(monkeypatch):
    monkeypatch.setattr(app.main, "MongoDatabase", FakeDatabase)

    with TestClient(app.main.app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "database": {"status": "healthy"},
    }


def test_health_reports_unhealthy_database(monkeypatch):
    class UnhealthyDatabase(FakeDatabase):
        healthy = False

    monkeypatch.setattr(app.main, "MongoDatabase", UnhealthyDatabase)

    with TestClient(app.main.app) as client:
        response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unhealthy",
        "database": {"status": "unhealthy"},
    }
