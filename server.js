#!/usr/bin/env node
'use strict';

/*
 * Compatibility entry point for the existing Node bridge.
 * Keeps the implementation in node-bridge/server.js and loads its
 * DevAssist route adapter into the same HTTP server.
 */
require('./node-bridge/devassist420-preload');

const { server } = require('./node-bridge/server');
const host = process.env.NODE_BRIDGE_HOST || '127.0.0.1';
const port = Number.parseInt(process.env.NODE_BRIDGE_PORT || '9899', 10);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('NODE_BRIDGE_PORT_INVALID');
}

server.listen(port, host, () => {
  process.stdout.write('[node-bridge] listening on ' + host + ':' + port + '\n');
});
