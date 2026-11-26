'use strict';
// `kig backup --out <dir>` and `kig restore <dir> --recovery-key <file> --anchor <file>`
// (features P1-07; architecture §13). Restore refusals name their category and leave live state unchanged.
const path = require('node:path');
const contracts = require('../core/contracts.cjs');
const backup = require('../cp/backup.cjs');
const supervisor = require('./supervisor.cjs');
const { UsageError, CommandError } = require('./main.cjs');

const homeOf = (values) => path.resolve(values.home || contracts.kigHome());

const backupCommand = {
  name: 'backup',
  describe: 'write a signed backup of the control plane, encrypted to the operator recovery key',
  usage: 'usage: node kig.cjs backup --out <dir> [--home <dir>]',
  options: { out: { type: 'string' }, home: { type: 'string' } },
  run({ values, positionals, io }) {
    if (positionals.length || !values.out) throw new UsageError('expected --out <dir>');
    let m;
    try { m = backup.createBackup(homeOf(values), values.out); } catch (e) {
      if (e instanceof backup.BackupError && e.code === 'output_not_empty') throw new CommandError('--out must be a new or empty directory');
      throw new CommandError('backup failed (is KIG_HOME initialized?)');
    }
    io.out(`BACKUP ${path.resolve(values.out)} id=${m.backup_id} epoch=${m.revocation_epoch} log_seq=${m.log_seq} schema=${m.schema_version}\n`);
    return 0;
  },
};

const restoreCommand = {
  name: 'restore',
  describe: 'verify a backup (signature, schema, digest, epoch, decryption, contents) and restore it',
  usage: 'usage: node kig.cjs restore <dir> --recovery-key <file> --anchor <file> [--home <dir>]',
  options: { 'recovery-key': { type: 'string' }, anchor: { type: 'string' }, home: { type: 'string' } },
  async run({ values, positionals, io }) {
    if (positionals.length !== 1 || !values['recovery-key'] || !values.anchor) throw new UsageError('expected <dir> --recovery-key <file> --anchor <file>');
    const home = homeOf(values);
    const env = { ...process.env, KIG_HOME: home };
    let r;
    try {
      r = await backup.restoreBackup(home, positionals[0], {
        recoveryKeyFile: path.resolve(values['recovery-key']), anchorFile: path.resolve(values.anchor),
        isRunning: async () => (await supervisor.status(home, env)).some((s) => s.healthy),
        stopCluster: () => supervisor.stop(home, env),
        startCluster: () => supervisor.start(home, env),
      });
    } catch (e) {
      if (e instanceof backup.RestoreError) throw new CommandError(`RESTORE REFUSED: ${e.category} (live state unchanged)`);
      if (e instanceof backup.BackupError) throw new CommandError('RESTORE REFUSED: the anchor file is unreadable (live state unchanged)');
      throw new CommandError('restore failed during the swap; check KIG_HOME/cp');
    }
    io.out(`RESTORED ${r.manifest.backup_id} epoch=${r.manifest.revocation_epoch} log_seq=${r.manifest.log_seq}` +
      `${r.quarantined ? `; previous registry kept as ${r.quarantined}` : ''}${r.restarted ? '; cluster restarted (recovery ran at CP start)' : ''}\n`);
    return 0;
  },
};

module.exports = { backup: backupCommand, restore: restoreCommand };
