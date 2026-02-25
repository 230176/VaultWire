function log(level, msg, meta = {}) {
  const safeMeta = { ...meta };
  delete safeMeta.password;
  delete safeMeta.refreshToken;
  delete safeMeta.privateKey;
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ level, msg, ...safeMeta, time: new Date().toISOString() }));
}
module.exports = {
  info: (m, meta) => log('info', m, meta),
  warn: (m, meta) => log('warn', m, meta),
  error: (m, meta) => log('error', m, meta)
};
