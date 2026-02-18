const express = require('express');
const routes = require('./routes');
const { commonMiddleware, errorHandler } = require('./common/middleware');

function createApp() {
  const app = express();
  commonMiddleware(app);
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true }));
  app.use('/api/v1', routes);
  app.use(errorHandler);
  return app;
}

module.exports = { createApp };
