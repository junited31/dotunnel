import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { rootChildEnvironment } from '../tools/release_verify/runner_dispatch.mjs';
import * as dispatcher from '../tools/release_verify/runner_dispatch.mjs';
import { pathToFileURL, fileURLToPath } from 'node:url';

const modulePath = fileURLToPath(new URL('../tools/release_verify/runner_dispatch.mjs', import.meta.url));
const moduleUrl = pathToFileURL(modulePath).href;
const SIGINT_MARKER = 'dispatcher-lifetime-after-sigint';

function untilLine(child, expected, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error(`missing child signal ${expected}`)), timeoutMs);
    const onData = (chunk) => {
      output += chunk.toString('utf8');
      const lines = output.split('\n');
      if (lines.includes(expected)) {
        clearTimeout(timer);
        child.stdout.off('data', onData);
        resolve();
      }
    };
    child.stdout.on('data', onData);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      reject(new Error(`child exited before ${expected}: ${code ?? signal}`));
    });
  });
}

function receiveOneLine(socket) {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      const end = bytes.indexOf(0x0a);
      if (end !== -1) resolve(bytes.subarray(0, end).toString('utf8'));
    });
    socket.once('error', reject);
  });
}

test('actual SIGINT sends one cancellation frame and keeps the dispatcher alive', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'runner-dispatch-signal-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const socketPath = path.join(directory, 'status.sock');
  let notice;
  let requests = 0;
  const server = net.createServer((socket) => {
    requests += 1;
    receiveOneLine(socket).then((line) => {
      notice = JSON.parse(line);
      socket.end('{"cancel_ack":true}\n');
    }, (error) => socket.destroy(error));
  });
  await new Promise((resolve, reject) => server.listen(socketPath, resolve).once('error', reject));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const childSource = `
    import { installCancellationHandler } from ${JSON.stringify(moduleUrl)};
    installCancellationHandler(process.env.TEST_CONTROL_SOCKET, BigInt(process.env.TEST_OUTER_DEADLINE_NS));
    process.stdout.write('dispatcher-ready\\n');
    setTimeout(() => process.stdout.write(${JSON.stringify(SIGINT_MARKER)} + '\\n'), 100);
    setInterval(() => {}, 1000);
  `;
  const child = spawn(process.execPath, ['--input-type=module', '--eval', childSource], {
    cwd: directory,
    env: {
      PATH: process.env.PATH ?? '',
      TEST_CONTROL_SOCKET: socketPath,
      TEST_OUTER_DEADLINE_NS: (process.hrtime.bigint() + 3_000_000_000n).toString(),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); });

  await untilLine(child, 'dispatcher-ready');
  const sentAt = process.hrtime.bigint();
  child.kill('SIGINT');
  await untilLine(child, SIGINT_MARKER);
  child.kill('SIGINT');
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.ok(notice, 'the root status stream receives the cancellation frame');
  assert.equal(requests, 1, 'repeated SIGINT preserves the first notice without duplicate frames');
  assert.deepEqual(Object.keys(notice).sort(), ['notice_ns', 'op']);
  assert.equal(notice.op, 'CANCEL');
  assert.match(notice.notice_ns, /^[1-9][0-9]{0,19}$/);
  assert.ok(BigInt(notice.notice_ns) >= sentAt);
  assert.ok(process.hrtime.bigint() - sentAt < 1_000_000_000n, 'the first notice is sent within one second');
  assert.equal(child.exitCode, null, 'SIGINT does not end the active entry process');

  child.kill('SIGTERM');
  await new Promise((resolve) => child.once('exit', resolve));
});

test('SIGTERM never becomes a cancellation notice', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'runner-dispatch-term-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const socketPath = path.join(directory, 'status.sock');
  let requests = 0;
  const server = net.createServer((socket) => {
    requests += 1;
    socket.destroy();
  });
  await new Promise((resolve, reject) => server.listen(socketPath, resolve).once('error', reject));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const childSource = `
    import { installCancellationHandler } from ${JSON.stringify(moduleUrl)};
    installCancellationHandler(process.env.TEST_CONTROL_SOCKET, BigInt(process.env.TEST_OUTER_DEADLINE_NS));
    process.stdout.write('dispatcher-ready\\n');
    setInterval(() => {}, 1000);
  `;
  const child = spawn(process.execPath, ['--input-type=module', '--eval', childSource], {
    cwd: directory,
    env: {
      PATH: process.env.PATH ?? '',
      TEST_CONTROL_SOCKET: socketPath,
      TEST_OUTER_DEADLINE_NS: (process.hrtime.bigint() + 3_000_000_000n).toString(),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  await untilLine(child, 'dispatcher-ready');
  child.kill('SIGTERM');
  const [, signal] = await new Promise((resolve) => child.once('exit', (code, signalName) => resolve([code, signalName])));
  assert.equal(signal, 'SIGTERM');
  assert.equal(requests, 0);
});

test('root child credentials remain isolated in an actual subprocess', () => {
  const forbidden = ['GITHUB_TOKEN', 'GH_TOKEN', 'GH_ENTERPRISE_TOKEN', 'ACTIONS_RUNTIME_TOKEN',
    'ACTIONS_RUNTIME_URL', 'ACTIONS_RESULTS_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
    'DOTUNNEL_BOOTSTRAP_MANIFEST', 'DOTUNNEL_SOURCE_DEV', 'DOTUNNEL_SOURCE_INO'];
  const previous = new Map(forbidden.map((key) => [key, process.env[key]]));
  let environment;
  try {
    forbidden.forEach((key) => { process.env[key] = `credential-marker-${key}`; });
    environment = rootChildEnvironment();
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    const forbidden = ['GITHUB_TOKEN', 'GH_TOKEN', 'GH_ENTERPRISE_TOKEN', 'ACTIONS_RUNTIME_TOKEN',
      'ACTIONS_RUNTIME_URL', 'ACTIONS_RESULTS_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
      'DOTUNNEL_BOOTSTRAP_MANIFEST', 'DOTUNNEL_SOURCE_DEV', 'DOTUNNEL_SOURCE_INO'];
    if (forbidden.some((key) => Object.hasOwn(process.env, key))) process.exitCode = 7;
  `], {
    encoding: 'utf8',
    env: environment,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('an unauthorized invocation fails before changing output or exposing credentials', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'runner-dispatch-denial-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, 'github-output');
  const original = 'preexisting-output\n';
  await writeFile(outputPath, original, { mode: 0o600 });
  const result = spawnSync(process.execPath, [modulePath], {
    cwd: directory,
    encoding: 'utf8',
    timeout: 3000,
    env: {
      PATH: process.env.PATH ?? '',
      GITHUB_REPOSITORY: 'foreign/repository',
      GITHUB_REF: 'refs/heads/main',
      GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_ACTOR: 'junited31',
      GITHUB_TRIGGERING_ACTOR: 'junited31',
      GITHUB_RUN_ID: '90000000000000000001',
      GITHUB_RUN_ATTEMPT: '1',
      GITHUB_SHA: 'a'.repeat(40),
      GITHUB_WORKSPACE: directory,
      GITHUB_JOB: 'receipt',
      GITHUB_TOKEN: 'contents-secret-marker',
      ACTIONS_RUNTIME_TOKEN: 'artifact-secret-marker',
      ACTIONS_RUNTIME_URL: 'https://runtime.invalid/',
      ACTIONS_RESULTS_URL: 'https://results.invalid/',
      GITHUB_OUTPUT: outputPath,
      DOTUNNEL_BOOTSTRAP_MANIFEST: '{"schema":1}',
      DOTUNNEL_RECEIPT_SCENARIO: 'normal',
    },
  });
  assert.notEqual(result.status, 0, 'foreign repository metadata is refused');
  assert.equal(await readFile(outputPath, 'utf8'), original);
  assert.ok(!result.stdout.includes('contents-secret-marker'));
  assert.ok(!result.stderr.includes('contents-secret-marker'));
  assert.ok(!result.stdout.includes('artifact-secret-marker'));
  assert.ok(!result.stderr.includes('artifact-secret-marker'));
});

test('status stream rejects an oversized response without buffering it unboundedly', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'runner-dispatch-stream-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const socketPath = path.join(directory, 'status.sock');
  const server = net.createServer((socket) => {
    socket.once('data', () => {
      socket.write(Buffer.alloc(65 * 1024, 0x61));
    });
  });
  await new Promise((resolve, reject) => server.listen(socketPath, resolve).once('error', reject));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const source = `
    import { requestControlStream } from ${JSON.stringify(moduleUrl)};
    try {
      await requestControlStream(process.env.TEST_CONTROL_SOCKET, { op: 'STATUS' }, BigInt(process.env.TEST_OUTER_DEADLINE_NS));
      process.exitCode = 9;
    } catch (error) {
      if (error?.code !== 'status-frame-too-large') process.exitCode = 8;
    }
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
    encoding: 'utf8',
    timeout: 3000,
    env: {
      PATH: process.env.PATH ?? '',
      TEST_CONTROL_SOCKET: socketPath,
      TEST_OUTER_DEADLINE_NS: (process.hrtime.bigint() + 2_000_000_000n).toString(),
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('GitHub comparison without invented head_commit admits only the bound ancestry', () => {
  const helper = 'a'.repeat(40);
  const workflow = 'b'.repeat(40);
  const comparison = {
    url: `https://api.github.com/repos/junited31/dotunnel/compare/${helper}...${workflow}`,
    status: 'ahead', ahead_by: 1, behind_by: 0, total_commits: 1,
    base_commit: { sha: helper }, merge_base_commit: { sha: helper },
  };
  assert.equal(dispatcher.comparisonIsAncestor(comparison, helper, workflow), true);
  for (const altered of [
    { ...comparison, status: 'behind' },
    { ...comparison, merge_base_commit: { sha: 'c'.repeat(40) } },
    { ...comparison, base_commit: { sha: workflow } },
    { ...comparison, url: comparison.url.replace(workflow, 'c'.repeat(40)) },
    { ...comparison, ahead_by: true },
  ]) {
    assert.equal(dispatcher.comparisonIsAncestor(altered, helper, workflow), false);
  }
});

test('trusted executable policy permits root owner-write but rejects shared-write and foreign ownership', async () => {
  const observed = await stat('/usr/bin/true', { bigint: true });
  assert.equal(dispatcher.trustedNodeStat(observed), true);
  for (const altered of [
    { isFile: () => true, uid: observed.uid, nlink: observed.nlink, mode: observed.mode | 0o020n },
    { isFile: () => true, uid: observed.uid, nlink: observed.nlink, mode: observed.mode | 0o002n },
    { isFile: () => true, uid: 1001n, nlink: observed.nlink, mode: observed.mode },
    { isFile: () => true, uid: observed.uid, nlink: 2n, mode: observed.mode },
    { isFile: () => true, uid: observed.uid, nlink: observed.nlink, mode: observed.mode & ~0o111n },
  ]) {
    assert.equal(dispatcher.trustedNodeStat(altered), false);
  }
});

test('terminal completion binds SIGINT notice, not its later receipt timestamp', () => {
  const terminal = {
    terminal: true, cancel_ack: true, cancel_notice_ns: '100',
    cancel_received_ns: '150', terminal_publication: 'LOCAL_PUBLISHED',
    readiness_publication: 'LOCAL_PUBLISHED', publisher_exit: 0,
  };
  assert.equal(dispatcher.terminalStatusReady(terminal, '100', false), true);
  assert.throws(() => dispatcher.terminalStatusReady(terminal, '150', false), /root-cancel-notice-mismatch/);
  assert.throws(() => dispatcher.terminalStatusReady({ ...terminal, cancel_ack: false }, '100', false), /root-cancel-not-acknowledged/);
  assert.throws(() => dispatcher.terminalStatusReady({ ...terminal, terminal_publication: 'FAILED' }, '100', false), /terminal-publication-failed/);
  assert.equal(dispatcher.terminalStatusReady({ ...terminal, terminal: false }, '100', false), false);
});

test('terminal record remains readable through a search-only directory descriptor', async () => {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(os.tmpdir(), 'dotunnel-terminal-search-'));
  let held;
  try {
    await writeFile(path.join(directory, 'terminal-status.json'), '{"terminal":true}\n', { mode: 0o444 });
    await chmod(directory, 0o111);
    held = await dispatcher.openSearchDirectory(directory);
    assert.equal(await readFile(`/proc/self/fd/${held.fd}/terminal-status.json`, 'utf8'), '{"terminal":true}\n');
    assert.equal((await held.stat({ bigint: true })).ino, (await stat(directory, { bigint: true })).ino);
  } finally {
    if (held) await held.close();
    await chmod(directory, 0o700);
    await rm(directory, { recursive: true, force: true });
  }
});
