'use strict';
// `kig rotate --file <file>`: versioned rotation with an epoch cutoff and a 30 s node-local grace
// window (features P1-04, D-06). The rotation itself runs inside the control plane (P4-D1).
const { call } = require('../core/http.cjs');
const { ports, url, ROUTES, NODE_IDS } = require('../core/contracts.cjs');
const { safe } = require('./text.cjs');
const { UsageError, CommandError } = require('./main.cjs');

const routePath = (route) => route.slice(route.indexOf(' ') + 1);
/** Reason codes arrive over HTTP: print them bare only if they are fixed-vocabulary codes. */
const code = (x) => (/^[a-z_]{1,64}$/.test(String(x)) ? String(x) : safe(x));
const nodeList = (list) => (Array.isArray(list) ? list.map((n) => (NODE_IDS.includes(n) ? n : safe(n))).join(',') : '');

/** POST to the CP; maps transport failures to one CommandError. */
async function cpPost(route, body, env = process.env, timeoutMs = 60000) {
  let response;
  try { response = await call(`${url(ports(env).cp)}${routePath(route)}`, 'POST', body, { timeoutMs }); }
  catch { throw new CommandError('control plane is not reachable (run kig up)'); }
  return response;
}

/** One line per rotation result; exit code 1 when it aborted. */
function describeRotation(r) {
  const head = `${safe(r.file_id)} ${r.from_version} -> ${r.to_version}`;
  if (r.status === 'complete') return { ok: true, line: `ROTATED ${head} epoch=${r.epoch} (complete: every node acknowledged; old version accepted only for transfers already in flight, for 30 s)` };
  if (r.status === 'committed') return { ok: true, line: `ROTATED ${head} epoch=${r.epoch} (committed; distribution pending on ${nodeList(r.pending_nodes)}: those nodes fail closed at lease expiry until they converge)` };
  return { ok: false, line: `ROTATION ABORTED ${head} (${code(r.reason)}${r.nodes ? `: ${nodeList(r.nodes)}` : ''}; version ${r.from_version} stays active)` };
}

module.exports = {
  name: 'rotate',
  describe: 'rotate a file to a new key version (epoch cutoff, 30 s grace for in-flight transfers)',
  usage: 'usage: node kig.cjs rotate --file <file>',
  options: { file: { type: 'string' } },
  async run({ values, positionals, io }) {
    if (positionals.length || !values.file) throw new UsageError('expected --file <file>');
    const response = await cpPost(ROUTES.cp.rotate, { file_id: values.file });
    if (response.status !== 200) throw new CommandError(`rotation refused (${code(response.json?.error || response.status)})`);
    const d = describeRotation(response.json);
    if (!d.ok) throw new CommandError(d.line);
    io.out(`${d.line}\n`);
    return 0;
  },
  cpPost, describeRotation, code, nodeList,
};
