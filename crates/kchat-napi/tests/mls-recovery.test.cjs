// Run against a freshly built .node file:
// KCHAT_NAPI_TEST_ADDON=/absolute/path/kchat.node node --test tests/mls-recovery.test.cjs
const assert = require('node:assert/strict');
const { mkdtempSync, readFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { test } = require('node:test');
const { UqMls } = require(process.env.KCHAT_NAPI_TEST_ADDON);

test('encrypted client keystore opens with a legacy plaintext group-status database', { timeout: 45000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kchat-napi-legacy-status-'));
  const clientPath = join(dir, 'client.sqlite');
  const seedStatus = join(dir, 'seed-status.sqlite');
  const legacyStatus = join(dir, 'legacy-status.sqlite');
  const password = 'ab'.repeat(32);
  const seed = new UqMls('alice', clientPath, seedStatus, 10, password, 5, 10);
  await seed.createGroup('target');
  const db = new DatabaseSync(legacyStatus);
  db.exec("CREATE TABLE group_statuses (group_id TEXT PRIMARY KEY, pending_operation TEXT NOT NULL); INSERT INTO group_statuses VALUES ('target', 'CREATE_GROUP')");
  db.close();
  const api = new UqMls('alice', clientPath, legacyStatus, 10, password, 5, 10);
  assert.deepEqual(await api.members('target'), ['alice']);
  assert.equal(readFileSync(legacyStatus).subarray(0, 16).toString(), 'SQLite format 3\0');
  assert.notEqual(readFileSync(clientPath).subarray(0, 16).toString(), 'SQLite format 3\0');
  await api.encryptMessage('target', [1, 2, 3]);
});

test('new N-API group-status databases retain the desktop plaintext contract', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kchat-napi-status-format-'));
  const clientPath = join(dir, 'client.sqlite');
  const statusPath = join(dir, 'status.sqlite');
  const api = new UqMls('alice', clientPath, statusPath, 10, 'cd'.repeat(32), 5, 10);
  await api.createGroup('target');
  assert.equal(readFileSync(statusPath).subarray(0, 16).toString(), 'SQLite format 3\0');
  assert.notEqual(readFileSync(clientPath).subarray(0, 16).toString(), 'SQLite format 3\0');
});

test('a deliberately shared client/status path retains its encrypted database contract', { timeout: 45000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kchat-napi-shared-keystore-'));
  const sharedPath = join(dir, 'shared.sqlite');
  const api = new UqMls('alice', sharedPath, sharedPath, 10, 'ef'.repeat(32), 5, 10);
  await api.createGroup('target');
  assert.deepEqual(await api.members('target'), ['alice']);
  assert.notEqual(readFileSync(sharedPath).subarray(0, 16).toString(), 'SQLite format 3\0');
});

test('equivalent shared paths use the database format without comparing path strings', { timeout: 45000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kchat-napi-shared-alias-'));
  const clientPath = join(dir, 'shared.sqlite');
  // Keep the alternate spelling: path.join would normalize the dot away.
  const statusPath = `${dir}/./shared.sqlite`;
  const password = 'ab'.repeat(32);
  const api = new UqMls('alice', clientPath, statusPath, 10, password, 5, 10);
  await api.createGroup('target');
  assert.deepEqual(await api.members('target'), ['alice']);
  assert.notEqual(readFileSync(clientPath).subarray(0, 16).toString(), 'SQLite format 3\0');

  const reopened = new UqMls('alice', statusPath, clientPath, 10, password, 5, 10);
  assert.deepEqual(await reopened.members('target'), ['alice']);
  await reopened.encryptMessage('target', [1, 2, 3]);
});

async function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'kchat-napi-mls-recovery-'));
  const mlsPath = join(dir, 'mls.sqlite');
  const statusPath = join(dir, 'status.sqlite');
  const api = new UqMls('alice', mlsPath, statusPath, 10, null, 5, 10);
  await api.createGroup('target');
  const db = new DatabaseSync(mlsPath);
  const status = new DatabaseSync(statusPath);
  t.after(() => { db.close(); status.close(); });
  return { api, db, status };
}

test('deleteGroup settles and removes corrupt group state; repeated calls succeed', { timeout: 15000 }, async (t) => {
  const { api, db } = await fixture(t);
  db.exec("UPDATE openmls_group_epoch_message_secrets SET message_secrets = X'ff'");
  await assert.rejects(api.members('target'), /MessageSecrets is invalid/);
  const logs = [];
  let onEnd;
  const endLogged = new Promise((resolve) => { onEnd = resolve; });
  await api.deleteGroup('target', (line) => {
    logs.push(line);
    if (line.includes('end delete group')) onEnd();
  });
  await api.deleteGroup('target');
  assert.equal(db.prepare('SELECT count(*) AS n FROM openmls_group_data').get().n, 0);
  assert.equal(db.prepare('SELECT count(*) AS n FROM openmls_group_epoch_message_secrets').get().n, 0);
  await assert.rejects(api.members('target'), /Group is not existed/);
  // Threadsafe log delivery can run after the Promise's completion.
  await endLogged;
  assert(logs.some((line) => line.includes('end delete group')));
});

test('status failure rejects the Promise and retry completes cleanup', { timeout: 15000 }, async (t) => {
  const { api, db, status } = await fixture(t);
  status.exec("CREATE TRIGGER fail_status BEFORE DELETE ON group_statuses BEGIN SELECT RAISE(ABORT, 'status cleanup failed'); END");
  await assert.rejects(api.deleteGroup('target'), /status cleanup failed/);
  assert.equal(db.prepare('SELECT count(*) AS n FROM openmls_group_data').get().n, 0);
  status.exec('DROP TRIGGER fail_status');
  await api.deleteGroup('target');
  assert.equal(status.prepare('SELECT count(*) AS n FROM group_statuses').get().n, 0);
});

test('read APIs retain consistent snapshots while commits change epoch', { timeout: 20000 }, async (t) => {
  const { api } = await fixture(t);
  const writer = (async () => {
    for (let i = 0; i < 60; i++) {
      await api.updateLeafNode('target');
      await api.mergePendingCommit('target');
    }
  })();
  const reader = (async () => {
    for (let i = 0; i < 300; i++) {
      const [members] = await Promise.all([
        api.members('target'), api.pendingCommit('target'),
        api.pendingProposals('target'), api.exportGroupInfo('target'),
      ]);
      assert.deepEqual(members, ['alice']);
    }
  })();
  await Promise.all([writer, reader]);
});
