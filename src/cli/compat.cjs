'use strict';
// @ts-check
// `kig compat`: proves this machine's Node supports everything KIG relies on
// (features P0-02, Appendix A). Child workers are this same file with --worker.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const provider = require('../crypto/provider.cjs');

const SELF = __filename;
const GENESIS = '0'.repeat(64);

function openDb(file) {
  const { DatabaseSync } = require('node:sqlite');
  return new DatabaseSync(file, { timeout: 5000 });
}

function initLog(file) {
  const db = openDb(file);
  const mode = db.prepare('PRAGMA journal_mode=WAL').get();
  db.exec('PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS log(seq INTEGER PRIMARY KEY, prev TEXT NOT NULL, h TEXT NOT NULL, v TEXT NOT NULL) STRICT;');
  db.close();
  return mode && mode.journal_mode;
}

function head(db) {
  return db.prepare('SELECT seq, h FROM log ORDER BY seq DESC LIMIT 1').get() || { seq: 0, h: GENESIS };
}

function append(db, v) {
  const t = head(db);
  const h = provider.sha256(Buffer.from(String(t.h) + v)).toString('hex');
  db.prepare('INSERT INTO log VALUES(?,?,?,?)').run(Number(t.seq) + 1, t.h, h, v);
}

function verifyLog(file) {
  const db = openDb(file);
  const rows = db.prepare('SELECT * FROM log ORDER BY seq').all();
  db.close();
  let prev = GENESIS;
  for (const r of rows) {
    if (r.prev !== prev || r.h !== provider.sha256(Buffer.from(prev + r.v)).toString('hex')) return { rows: rows.length, ok: false, rowsData: rows };
    prev = String(r.h);
  }
  return { rows: rows.length, ok: true, rowsData: rows };
}

/** Child-process side. */
async function worker(mode, file, arg) {
  if (mode === 'append') {
    const db = openDb(file);
    for (let i = 0; i < Number(arg); i++) {
      db.exec('BEGIN IMMEDIATE');
      try { append(db, `${process.pid}:${i}`); db.exec('COMMIT'); } catch (e) { db.exec('ROLLBACK'); throw e; }
    }
    db.close();
  } else if (mode === 'hang') {
    const db = openDb(file);
    db.exec('BEGIN IMMEDIATE');
    append(db, 'partial');
    process.stdout.write('in-txn\n');
    setInterval(() => {}, 1000);
  } else if (mode === 'quiet') {
    // Mirrors an entry point: warnings suppressed first, then experimental features used.
    openDb(':memory:').close();
    const { publicKey } = provider.kemGenerate();
    await provider.kemEncapsulateRaw(await provider.kemExportRawPublic(publicKey));
  }
}

function runChild(args, { onStdout } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SELF, '--worker', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; if (onStdout) onStdout(stdout, child); });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

async function run() {
  const results = (await provider.selfTest()).map((r) => ({ ...r }));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-compat-'));
  const add = (name, pass, detail) => results.push({ name, pass: !!pass, detail });
  try {
    // 1. WAL + STRICT
    try {
      const f = path.join(dir, 'strict.db');
      const mode = initLog(f);
      const db = openDb(f);
      let strict = false;
      try { db.prepare('INSERT INTO log VALUES(?,?,?,?)').run('not-an-int', 'a', 'b', 'c'); } catch { strict = true; }
      db.close();
      add('sqlite wal + strict tables', mode === 'wal' && strict, `journal_mode=${mode}`);
    } catch (e) { add('sqlite wal + strict tables', false, String(e && e.message)); }

    // 2. Concurrency: 8 processes x 25 appends on a pre-created WAL database.
    try {
      const f = path.join(dir, 'concurrent.db');
      initLog(f);
      const runs = await Promise.all(Array.from({ length: 8 }, () => runChild(['append', f, '25'])));
      const v = verifyLog(f);
      add('sqlite 8 processes x 25 chained appends', runs.every((r) => r.code === 0) && v.rows === 200 && v.ok,
        `rows=${v.rows} chain=${v.ok ? 'valid' : 'BROKEN'}`);
    } catch (e) { add('sqlite 8 processes x 25 chained appends', false, String(e && e.message)); }

    // 3. SIGKILL inside an open transaction.
    try {
      const f = path.join(dir, 'kill.db');
      initLog(f);
      await runChild(['append', f, '3']);
      const r = await runChild(['hang', f], { onStdout: (out, child) => { if (out.includes('in-txn')) child.kill('SIGKILL'); } });
      const v = verifyLog(f);
      add('sqlite SIGKILL inside transaction leaves no partial row',
        r.signal === 'SIGKILL' && v.ok && v.rows === 3 && !v.rowsData.some((x) => x.v === 'partial'), `rows=${v.rows}`);
    } catch (e) { add('sqlite SIGKILL inside transaction leaves no partial row', false, String(e && e.message)); }

    // 4. VACUUM INTO (backup path, architecture §13).
    try {
      const f = path.join(dir, 'concurrent.db'), copy = path.join(dir, 'copy.db');
      const db = openDb(f);
      db.prepare('VACUUM INTO ?').run(copy);
      db.close();
      const v = verifyLog(copy);
      add('sqlite VACUUM INTO copy readable', v.ok && v.rows === 200, `rows=${v.rows}`);
    } catch (e) { add('sqlite VACUUM INTO copy readable', false, String(e && e.message)); }

    // 5. No ExperimentalWarning text reaches stderr from an entry point.
    try {
      const r = await runChild(['quiet']);
      add('entry point stderr silent after warning suppression', r.code === 0 && r.stderr === '', `stderr bytes=${r.stderr.length}`);
    } catch (e) { add('entry point stderr silent after warning suppression', false, String(e && e.message)); }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return results;
}

/** CLI entry: prints PASS/FAIL per check plus INFO lines; returns exit code. */
async function main() {
  process.stdout.write(`INFO node ${process.version} ${process.platform}-${process.arch} openssl ${process.versions.openssl} sqlite ${process.versions.sqlite}\n`);
  const results = await run();
  for (const r of results) process.stdout.write(`${r.pass ? 'PASS' : 'FAIL'} ${r.name}${r.pass || !r.detail ? '' : ` (${r.detail})`}\n`);
  return results.every((r) => r.pass) ? 0 : 1;
}

if (require.main === module && process.argv[2] === '--worker') {
  process.removeAllListeners('warning');
  worker(process.argv[3], process.argv[4], process.argv[5]).catch(() => { process.exitCode = 1; });
}

module.exports = { run, main };
