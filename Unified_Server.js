#!/usr/bin/env node
'use strict';

/* Canonical Node REST/WebSocket relay on port 9899. */
require('./node-bridge/devassist420-preload');
const { server } = require('./node-bridge/server');

function start() {
  const host = process.env.UNIFIED_HOST || process.env.NODE_BRIDGE_HOST || '127.0.0.1';
  const rawPort = process.env.PORT_UNIFIED || process.env.NODE_BRIDGE_PORT || '9899';
  const port = Number.parseInt(rawPort, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('UNIFIED_SERVER_PORT_INVALID');
  server.listen(port, host, () => {
    process.stdout.write('[unified] listening on http://' + host + ':' + port + '\n');
  });
  server.on('error', error => {
    process.stderr.write('[unified] server error: ' + error.message + '\n');
    process.exitCode = 1;
  });
  return server;
}

if (require.main === module) start();
module.exports = { start, server };
