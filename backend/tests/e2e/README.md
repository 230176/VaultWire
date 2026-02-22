# Optional E2E tests with MongoDB container

These tests are intended for environments where Docker is available.

Example flow:
1. `docker compose up -d mongo`
2. Set `MONGODB_URI=mongodb://localhost:27017/vaultwire_test`
3. Run a dedicated e2e suite (not included in default CI run).

The default Jest suite in this repository uses unit tests with model mocking.
