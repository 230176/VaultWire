const jwt = require('jsonwebtoken');
const env = require('../../config/env');

let ioRef = null;

function initSocket(server) {
  const { Server } = require('socket.io');
  ioRef = new Server(server, {
    cors: { origin: env.CORS_ORIGIN, credentials: true }
  });

  ioRef.use((socket, next) => {
    try {
      const token = socket.handshake.auth?.token;
      if (!token) return next(new Error('missing token'));
      const payload = jwt.verify(token, env.JWT_ACCESS_SECRET);
      socket.user = payload;
      next();
    } catch (e) {
      next(new Error('unauthorized'));
    }
  });

  ioRef.on('connection', (socket) => {
    socket.join(`user:${socket.user.sub}`);
  });

  return ioRef;
}

function emitToUser(userId, event, payload) {
  if (!ioRef) return;
  ioRef.to(`user:${userId}`).emit(event, payload);
}

module.exports = { initSocket, emitToUser };
