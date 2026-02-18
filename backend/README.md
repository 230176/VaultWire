# Backend

## Environment Variables

Required:
- `PORT`
- `MONGODB_URI`
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `ACCESS_TOKEN_TTL`
- `REFRESH_TOKEN_TTL_DAYS`
- `SERVER_MASTER_KEY` (64 hex chars)
- `ADMIN_BOOTSTRAP_TOKEN`
- `CORS_ORIGIN`

Optional:
- `RATE_LIMIT_WINDOW_MS` (default 60000)
- `RATE_LIMIT_MAX` (default 120)
- `NODE_ENV` (`development`/`production`/`test`)

## Run

```bash
npm install
npm run dev
```
