'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { runKig } = require('./run-kig.cjs');
const { NODE_IDS } = require('../../src/core/contracts.cjs');

function freshHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'kig-home-'));
}

async function freePortBase() {
  for (let attempt = 0; attempt < 20; attempt++) {
    // Stay below the usual ephemeral client-port range so our own HTTP probes
    // cannot claim the server ports as outbound source ports after we release them.
    const base = 10000 + Math.floor(Math.random() * 15000);
    const servers = [];
    try {
      for (let p = base; p <= base + 3; p++) {
        const s = net.createServer(); servers.push(s);
        await new Promise((resolve, reject) => s.once('error', reject).listen(p, '127.0.0.1', resolve));
      }
      await Promise.all(servers.map((s) => new Promise((resolve, reject) => s.close((e) => e ? reject(e) : resolve()))));
      return base;
    } catch {
      await Promise.all(servers.filter((s) => s.listening).map((s) => new Promise((resolve) => s.close(resolve))));
    }
  }
  throw new Error('could not reserve four consecutive loopback ports');
}

/** Start a test cluster and return its URLs plus a cleanup function. */
async function startCluster(home, { nodes = NODE_IDS } = {}) {
  if (!Array.isArray(nodes) || nodes.length !== 3 || new Set(nodes).size !== 3 || nodes.some((n) => !NODE_IDS.includes(n))) {
    throw new TypeError('nodes must be A, B and C');
  }
  const base = await freePortBase();
  const env = { KIG_HOME: path.resolve(home), KIG_PORT_BASE: String(base) };
  if (!fs.existsSync(path.join(home, 'cp', 'registry.db'))) {
    const initialized = runKig(['init'], { env, timeoutMs: 30000 });
    if (initialized.code !== 0) throw new Error(`cluster initialization failed: ${initialized.stderr || initialized.stdout}`);
  }
  const started = runKig(['up'], { env, timeoutMs: 15000 });
  if (started.code !== 0) {
    const logs = ['cp', ...NODE_IDS].map((id) => {
      const file = path.join(home, 'run', `${id}.log`);
      return fs.existsSync(file) ? `${id}: ${fs.readFileSync(file, 'utf8').slice(-2000)}` : '';
    }).filter(Boolean).join('\n');
    throw new Error(`cluster failed to start on port base ${base}: ${started.stderr || started.stdout}\n${logs}`);
  }
  let stopped = false;
  return {
    cpUrl: `http://127.0.0.1:${base}`,
    nodeUrls: Object.fromEntries(nodes.map((n) => [n, `http://127.0.0.1:${base + NODE_IDS.indexOf(n) + 1}`])),
    async stop() {
      if (stopped) return;
      const result = runKig(['down'], { env, timeoutMs: 10000 });
      if (result.code !== 0) throw new Error(`cluster failed to stop: ${result.stderr || result.stdout}`);
      stopped = true;
    },
  };
}

module.exports = { freshHome, startCluster };
