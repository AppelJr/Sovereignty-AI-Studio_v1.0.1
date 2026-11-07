#!/usr/bin/env node
'use strict';

// Backward-compatible entrypoint. The canonical Node relay is Unified_Server.js.
const { start } = require('./Unified_Server');
if (require.main === module) start();
module.exports = require('./Unified_Server');
