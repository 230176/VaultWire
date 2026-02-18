const http = require('http');
const { createApp } = require('./app');
const { connectDB } = require('./config/db');
const env = require('./config/env');
const { initSocket } = require('./modules/realtime/socket');
const logger = require('./common/logger');
const { ensureSuperAdmin } = require('./modules/auth/superadmin.seed');

async function start() {
  await connectDB();
  await ensureSuperAdmin();
  const app = createApp();
  const server = http.createServer(app);
  initSocket(server);
  server.listen(env.PORT, () => {
    logger.info('server_started', { port: env.PORT });
  });
}

start().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});
