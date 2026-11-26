'use strict';
const { tx } = require('../store/db.cjs');

const mono = () => process.hrtime.bigint();
function get(db, key) {
  return db.prepare('SELECT v FROM lease WHERE k=?').get(key)?.v ?? null;
}
function set(db, key, value) {
  db.prepare('INSERT INTO lease(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(key, String(value));
}
function refresh(db, leaseMs) {
  const until = mono() + BigInt(leaseMs) * 1_000_000n;
  set(db, 'lease_until_mono_ns', until.toString());
}
function isPartitioned(db) { return get(db, 'partitioned') === '1'; }
function setPartitioned(db, value) {
  tx(db, () => {
    if (value) set(db, 'partitioned', '1');
    else db.prepare("DELETE FROM lease WHERE k='partitioned'").run();
  });
}
function leaseValid(db) {
  try {
    const until = get(db, 'lease_until_mono_ns');
    return until !== null && BigInt(until) > mono() && Number.isSafeInteger(Number(get(db, 'applied_epoch'))) && Number(get(db, 'applied_epoch')) > 0;
  } catch { return false; }
}
module.exports = { leaseValid, refresh, get, set, isPartitioned, setPartitioned, monotonicNs: () => mono().toString() };
