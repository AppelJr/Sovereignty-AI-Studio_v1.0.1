'use strict';

/* Loaded only for the canonical node-bridge process. It wraps the HTTP
 * request listener so DevAssist420 shares port 9899 instead of creating a
 * competing second server. All other Node bridge routes remain unchanged. */
const http = require('node:http');
const devassist = require('./devassist420-handler');
const originalCreateServer = http.createServer;

http.createServer = function createServerWithDevAssist(...args) {
  if (typeof args[0] !== 'function') return originalCreateServer.apply(http, args);
  const originalListener = args[0];
  args[0] = (req, res) => {
    try {
      if (devassist.route(req, res)) return;
    } catch (error) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ state: 'DENY', reason: error.message }));
      return;
    }
    return originalListener(req, res);
  };
  return originalCreateServer.apply(http, args);
};
