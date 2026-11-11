'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocketServer } = require('ws');

async function main() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'devassist-inference-status-'));
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve, reject) => {
    wss.once('listening', resolve);
    wss.once('error', reject);
  });
  const address = wss.address();
  wss.on('connection', socket => {
    socket.send(JSON.stringify({ type: 'handshake_ack', port: 9897 }));
    socket.on('message', raw => {
      let message;
      try { message = JSON.parse(String(raw)); } catch { return; }
      if (message.type === 'status') {
        socket.send(JSON.stringify({
          type: 'status_response',
          inference: {
            configured: false,
            loaded: false,
            ready: false,
            providers: { local_gguf: { ok: false, reason: 'model_missing' } }
          }
        }));
      }
    });
  });

  process.env.SOVEREIGN_PYTHON_WS_URL = `ws://127.0.0.1:${address.port}`;
  process.env.SOVEREIGN_STATE_PATH = path.join(temp, 'missing-canonical-state.json');
  process.env.SCAR_PATH = path.join(temp, 'scar.jsonl');

  try {
    const { status } = require('../node-bridge/devassist420-handler');
    const result = await status();
    assert.equal(result.python.state, 'ONLINE');
    assert.equal(result.inference.state, 'UNAVAILABLE');
    assert.equal(result.inference.ready, undefined);
    assert.equal(result.readiness.ready, false);
    assert.equal(result.governed_pipeline.state, 'UNWIRED');
    assert.equal(result.governed_pipeline.output_authorized, false);
    assert.ok(result.readiness.blockers.includes('LOCAL_MODEL_UNAVAILABLE'));
    assert.ok(result.readiness.blockers.includes('GOVERNED_CHAIN_NOT_CONNECTED'));
    console.log('PASS: DevAssist420 does not report ready when local inference is unavailable');
  } finally {
    await new Promise(resolve => wss.close(resolve));
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
