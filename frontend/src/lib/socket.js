import { io } from 'socket.io-client';

let socket = null;

export function connectSocket(token) {
  const URL = import.meta.env.VITE_SOCKET_URL || 'http://localhost:5000';
  socket = io(URL, { auth: { token } });
  return socket;
}

export function getSocket() {
  return socket;
}
