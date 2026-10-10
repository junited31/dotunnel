import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants as fsConstants, promises as fs } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TextDecoder } from 'node:util';

const OWNER = 'junited31';
const REPOSITORY = 'junited31/dotunnel';
const PROTECTED_REF = 'refs/heads/main';
const EVENT = 'workflow_dispatch';
const UPLOAD_ACTION_COMMIT = 'ea165f8d65b6e75b540449e92b4886f43607fa02';
const REQUIRED_CHECKS = Object.freeze(['Secret scan', 'Python 3.11', 'Python 3.13']);
const CHECK_APP_ID = 15368;
const REQUIRED_FILES = Object.freeze([
  'runner_prepare.py',
  'runner_policy.py',
  'runner_runtime.py',
  'runner_artifact.py',
  'runner_dispatch.mjs',
  'upload-index.js',
]);
const OPTIONAL_FILES = Object.freeze(['upload-action.yml', 'package-lock.json']);
const SOURCE_CHECKOUT_RELATIVE = '.verification-runner-source';
const SOURCE_PATHS = Object.freeze({
  'runner_prepare.py': 'tools/release_verify/runner_prepare.py',
  'runner_policy.py': 'tools/release_verify/runner_policy.py',
  'runner_runtime.py': 'tools/release_verify/runner_runtime.py',
  'runner_artifact.py': 'tools/release_verify/runner_artifact.py',
  'runner_dispatch.mjs': 'tools/release_verify/runner_dispatch.mjs',
  'upload-index.js': '.verification-upload-action/dist/upload/index.js',
  'upload-action.yml': '.verification-upload-action/action.yml',
  'package-lock.json': '.verification-upload-action/package-lock.json',
});
const MAX_MANIFEST_BYTES = 4096;
const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const MAX_UPLOAD_INDEX_BYTES = 12 * 1024 * 1024;
const MAX_OTHER_FILE_BYTES = 1024 * 1024;
const MAX_RUNTIME_PAYLOAD_BYTES = 16 * 1024;
const MAX_CONTROL_REQUEST_BYTES = 4 * 1024;
const MAX_CONTROL_RESPONSE_BYTES = 64 * 1024;
const MAX_GITHUB_RESPONSE_BYTES = 1024 * 1024;
const JOB_LIMIT_NS = 600_000_000_000n;
const MIN_JOB_WINDOW_NS = 540_000_000_000n;
const CANCEL_DELIVERY_NS = 1_000_000_000n;
const CONTROL_POLL_MS = 250;
const API_ROOT = 'https://api.github.com';
const ROOT_PATH = '/run';
const FIXED_NATIVE_BINARIES = Object.freeze([
  '/usr/bin/sudo',
  '/usr/bin/systemd-run',
  '/usr/bin/systemctl',
  '/usr/bin/bash',
  '/usr/bin/mount',
  '/usr/bin/umount',
  '/usr/bin/cp',
  '/usr/bin/prlimit',
  '/usr/bin/timeout',
  '/usr/bin/stat',
  '/usr/bin/sha256sum',
  '/usr/bin/chmod',
  '/usr/bin/mkdir',
  '/usr/bin/rmdir',
  '/usr/bin/rm',
  '/usr/bin/sync',
  '/usr/bin/mv',
  '/usr/bin/cat',
  '/usr/bin/base64',
]);
const ROOT_PYTHON = '/usr/bin/python3';
const ROOT_CHILD_ENV = Object.freeze({
  PATH: '/usr/sbin:/usr/bin:/sbin:/bin',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  HOME: '/root',
});
const UTF8 = new TextDecoder('utf-8', { fatal: true });

class DispatchError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new DispatchError(code);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

class StrictJsonParser {
  constructor(raw, maxBytes) {
    if (!Buffer.isBuffer(raw)) fail('invalid-json-input');
    if (raw.length > maxBytes) fail('json-input-too-large');
    try {
      this.text = UTF8.decode(raw);
    } catch {
      fail('invalid-json-utf8');
    }
    this.index = 0;
    this.items = 0;
  }

  parse() {
    this.space();
    const value = this.value(0);
    this.space();
    if (this.index !== this.text.length) fail('invalid-json-trailing-data');
    return value;
  }

  space() {
    while (this.index < this.text.length && /[\u0009\u000a\u000d\u0020]/u.test(this.text[this.index])) this.index += 1;
  }

  value(depth) {
    if (depth > 32 || this.index >= this.text.length) fail('invalid-json-depth-or-eof');
    this.items += 1;
    if (this.items > 8192) fail('invalid-json-complexity');
    const current = this.text[this.index];
    if (current === '{') return this.object(depth + 1);
    if (current === '[') return this.array(depth + 1);
    if (current === '"') return this.string();
    if (current === 't' && this.text.startsWith('true', this.index)) {
      this.index += 4;
      return true;
    }
    if (current === 'f' && this.text.startsWith('false', this.index)) {
      this.index += 5;
      return false;
    }
    if (current === 'n' && this.text.startsWith('null', this.index)) {
      this.index += 4;
      return null;
    }
    return this.number();
  }

  string() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        try {
          return JSON.parse(this.text.slice(start, this.index));
        } catch {
          fail('invalid-json-string');
        }
      }
      if (code < 0x20) fail('invalid-json-string');
      if (code === 0x5c) {
        this.index += 1;
        if (this.index >= this.text.length) fail('invalid-json-string');
        const escaped = this.text[this.index];
        if (escaped === 'u') {
          const digits = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(digits)) fail('invalid-json-string');
          this.index += 5;
          continue;
        }
        if (!/["\\/bfnrt]/u.test(escaped)) fail('invalid-json-string');
      }
      this.index += 1;
    }
    fail('invalid-json-string');
  }

  number() {
    const remaining = this.text.slice(this.index);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(remaining);
    if (!match) fail('invalid-json-value');
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) fail('invalid-json-number');
    return value;
  }

  object(depth) {
    this.index += 1;
    this.space();
    const result = Object.create(null);
    if (this.text[this.index] === '}') {
      this.index += 1;
      return result;
    }
    while (true) {
      if (this.text[this.index] !== '"') fail('invalid-json-object-key');
      const key = this.string();
      if (Object.hasOwn(result, key)) fail('duplicate-json-key');
      this.space();
      if (this.text[this.index] !== ':') fail('invalid-json-object-separator');
      this.index += 1;
      this.space();
      result[key] = this.value(depth);
      this.space();
      const separator = this.text[this.index];
      if (separator === '}') {
        this.index += 1;
        return result;
      }
      if (separator !== ',') fail('invalid-json-object-separator');
      this.index += 1;
      this.space();
    }
  }

  array(depth) {
    this.index += 1;
    this.space();
    const result = [];
    if (this.text[this.index] === ']') {
      this.index += 1;
      return result;
    }
    while (true) {
      result.push(this.value(depth));
      this.space();
      const separator = this.text[this.index];
      if (separator === ']') {
        this.index += 1;
        return result;
      }
      if (separator !== ',') fail('invalid-json-array-separator');
      this.index += 1;
      this.space();
    }
  }
}

function parseStrictJson(raw, maxBytes) {
  return new StrictJsonParser(raw, maxBytes).parse();
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  if (typeof value === 'string' || typeof value === 'boolean' || value === null) return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  fail('invalid-canonical-json-value');
}

function positiveId(value) {
  return typeof value === 'string' && /^[1-9][0-9]{0,19}$/u.test(value);
}

function runNames(run, attempt) {
  if (!positiveId(run) || !positiveId(attempt)) fail('invalid-run-identity');
  const prefix = `dotunnelpilot${run}a${attempt}`;
  return Object.freeze({
    run,
    attempt,
    prefix,
    root: `/run/${prefix}`,
    control: `/run/${prefix}-control`,
    source: `/run/${prefix}-source`,
    sourceTemp: `/run/${prefix}-source-tmp`,
    stage: `/run/${prefix}-stage`,
    native: `/run/${prefix}-native`,
    bootstrapUnit: `${prefix}-bootstrap.service`,
    bootstrapRecoveryUnit: `dotunnelbootstraprecovery${run}a${attempt}.service`,
  });
}

function readInvocation(env) {
  const fixed = {
    schema: 1,
    repository: REPOSITORY,
    ref: PROTECTED_REF,
    event: EVENT,
    actor: OWNER,
    triggering_actor: OWNER,
  };
  if (env.GITHUB_REPOSITORY !== REPOSITORY || env.GITHUB_REF !== PROTECTED_REF
      || env.GITHUB_EVENT_NAME !== EVENT || env.GITHUB_ACTOR !== OWNER
      || env.GITHUB_TRIGGERING_ACTOR !== OWNER) fail('untrusted-invocation');
  const names = runNames(env.GITHUB_RUN_ID, env.GITHUB_RUN_ATTEMPT);
  if (typeof env.GITHUB_SHA !== 'string' || !/^[0-9a-f]{40}$/u.test(env.GITHUB_SHA)) fail('invalid-source-commit');
  if (typeof env.GITHUB_JOB !== 'string' || !/^[A-Za-z_][A-Za-z0-9_-]{0,99}$/u.test(env.GITHUB_JOB)) fail('invalid-job-identity');
  const context = Object.freeze({
    ...fixed,
    run: names.run,
    attempt: names.attempt,
  });
  return Object.freeze({ context, names, sourceCommit: env.GITHUB_SHA, job: env.GITHUB_JOB });
}

function parseBootstrapManifest(raw) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > MAX_MANIFEST_BYTES) fail('invalid-bootstrap-manifest');
  const manifest = parseStrictJson(Buffer.from(raw, 'utf8'), MAX_MANIFEST_BYTES);
  if (!exactKeys(manifest, ['schema', 'commit', 'files', 'upload_action_commit'])
      || manifest.schema !== 1 || typeof manifest.commit !== 'string'
      || !/^[0-9a-f]{40}$/u.test(manifest.commit)
      || manifest.upload_action_commit !== UPLOAD_ACTION_COMMIT
      || !isRecord(manifest.files)) fail('invalid-bootstrap-manifest');
  const files = Object.create(null);
  const names = Object.keys(manifest.files).sort();
  const permitted = new Set([...REQUIRED_FILES, ...OPTIONAL_FILES]);
  if (REQUIRED_FILES.some((name) => !Object.hasOwn(manifest.files, name))
      || names.some((name) => !permitted.has(name))) fail('invalid-bootstrap-file-set');
  for (const name of names) {
    const digest = manifest.files[name];
    if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/u.test(digest)) fail('invalid-bootstrap-file-digest');
    files[name] = digest;
  }
  return Object.freeze({
    schema: 1,
    commit: manifest.commit,
    files: Object.freeze(files),
    upload_action_commit: UPLOAD_ACTION_COMMIT,
  });
}

function runtimeCredentials(env) {
  const token = env.ACTIONS_RUNTIME_TOKEN;
  const runtimeUrl = env.ACTIONS_RUNTIME_URL;
  const resultsUrl = env.ACTIONS_RESULTS_URL;
  if (typeof token !== 'string' || token.length < 1 || Buffer.byteLength(token, 'utf8') > 8192
      || !/^[\x21-\x7e]+$/u.test(token)) fail('runtime-credential-unavailable');
  for (const [name, value] of [['ACTIONS_RUNTIME_URL', runtimeUrl], ['ACTIONS_RESULTS_URL', resultsUrl]]) {
    if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 2048
        || !/^[\x21-\x7e]+$/u.test(value)) fail('runtime-url-unavailable');
    let parsed;
    try { parsed = new URL(value); } catch { fail('runtime-url-unavailable'); }
    if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password || parsed.hash) fail('runtime-url-unavailable');
  }
  return { ACTIONS_RUNTIME_TOKEN: token, ACTIONS_RUNTIME_URL: runtimeUrl, ACTIONS_RESULTS_URL: resultsUrl };
}


function fileIdentity(stat) {
  return [stat.dev, stat.ino, stat.mode, stat.uid, stat.gid, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
}

function ensureDirectoryStat(stat, uid, gid, expectedMode) {
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(uid) || stat.gid !== BigInt(gid)
      || Number(stat.mode & 0o777n) !== expectedMode || (stat.mode & 0o022n) !== 0n) fail('unsafe-source-directory');
}

function maxSourceFile(name) {
  return name === 'upload-index.js' ? MAX_UPLOAD_INDEX_BYTES : MAX_OTHER_FILE_BYTES;
}

async function openChildDirectory(parentFd, name, uid, gid) {
  const directoryPath = `/proc/self/fd/${parentFd}/${name}`;
  let fd;
  try {
    fd = await fs.open(directoryPath, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC);
    const held = await fd.stat({ bigint: true });
    ensureDirectoryStat(held, uid, gid, 0o755);
    const named = await fs.lstat(directoryPath, { bigint: true });
    ensureDirectoryStat(named, uid, gid, 0o755);
    if (fileIdentity(held) !== fileIdentity(named)) fail('source-directory-changed');
    return fd;
  } catch (error) {
    if (fd) await fd.close().catch(() => {});
    if (error instanceof DispatchError) throw error;
    fail('source-directory-unavailable');
  }
}

function relativeParts(relative) {
  const parts = relative.split('/');
  if (parts.some((part) => !part || part === '.' || part === '..')) fail('invalid-fixed-source-path');
  return parts;
}

async function openFixedFile(rootFd, relative, uid, gid) {
  const parts = relativeParts(relative);
  let directory = rootFd;
  const opened = [];
  try {
    for (const part of parts.slice(0, -1)) {
      const child = await openChildDirectory(directory.fd ?? directory, part, uid, gid);
      opened.push(child);
      directory = child;
    }
    const directoryFd = directory.fd ?? directory;
    const filePath = `/proc/self/fd/${directoryFd}/${parts.at(-1)}`;
    const handle = await fs.open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC | fsConstants.O_NONBLOCK);
    return { handle, filePath, opened };
  } catch (error) {
    for (const handle of opened.reverse()) await handle.close().catch(() => {});
    if (error instanceof DispatchError) throw error;
    fail('source-file-unavailable');
  }
}

async function inspectSources(workspaceValue, manifest) {
  if (typeof workspaceValue !== 'string' || !path.isAbsolute(workspaceValue) || path.resolve(workspaceValue) !== workspaceValue) fail('invalid-workspace-path');
  let canonicalWorkspace;
  try { canonicalWorkspace = await fs.realpath(workspaceValue); } catch { fail('source-workspace-unavailable'); }
  let canonicalCwd;
  try { canonicalCwd = await fs.realpath(process.cwd()); } catch { fail('source-cwd-unavailable'); }
  if (canonicalWorkspace !== workspaceValue || canonicalCwd !== canonicalWorkspace) fail('source-cwd-mismatch');

  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid < 0) fail('runner-identity-unavailable');
  let rootHandle;
  try {
    rootHandle = await fs.open(workspaceValue, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC);
  } catch { fail('source-workspace-unavailable'); }
  const directories = [rootHandle];
  const files = [];
  try {
    const rootStat = await rootHandle.stat({ bigint: true });
    ensureDirectoryStat(rootStat, uid, gid, 0o755);
    const namedRoot = await fs.lstat(workspaceValue, { bigint: true });
    ensureDirectoryStat(namedRoot, uid, gid, 0o755);
    if (fileIdentity(rootStat) !== fileIdentity(namedRoot)) fail('source-workspace-changed');
    let total = 0;
    for (const destination of Object.keys(manifest.files).sort()) {
      const sourceRelative = SOURCE_PATHS[destination];
      if (!sourceRelative) fail('invalid-fixed-source-path');
      const file = await openFixedFile(rootHandle.fd, sourceRelative, uid, gid);
      directories.push(...file.opened);
      const stat = await file.handle.stat({ bigint: true });
      if (!stat.isFile() || stat.uid !== BigInt(uid) || stat.gid !== BigInt(gid) || stat.nlink !== 1n
          || Number(stat.mode & 0o777n) !== 0o644 || (stat.mode & 0o022n) !== 0n
          || stat.size > BigInt(maxSourceFile(destination))) fail('unsafe-source-file');
      const size = Number(stat.size);
      if (!Number.isSafeInteger(size) || size < 1) fail('unsafe-source-file-size');
      total += size;
      if (total > MAX_SOURCE_BYTES) fail('source-closure-too-large');
      const hash = createHash('sha256');
      const buffer = Buffer.allocUnsafe(64 * 1024);
      let position = 0;
      while (true) {
        const result = await file.handle.read(buffer, 0, buffer.length, position);
        if (result.bytesRead === 0) break;
        position += result.bytesRead;
        if (position > size) fail('source-file-grew');
        hash.update(buffer.subarray(0, result.bytesRead));
      }
      const after = await file.handle.stat({ bigint: true });
      const named = await fs.lstat(file.filePath, { bigint: true });
      const beforeIdentity = fileIdentity(stat);
      if (beforeIdentity !== fileIdentity(after) || beforeIdentity !== fileIdentity(named) || position !== size) fail('source-file-changed');
      if (hash.digest('hex') !== manifest.files[destination]) fail('source-file-digest-mismatch');
      files.push(Object.freeze({
        destination,
        sourceRelative,
        digest: manifest.files[destination],
        size,
        dev: stat.dev.toString(),
        ino: stat.ino.toString(),
        uid: stat.uid.toString(),
        gid: stat.gid.toString(),
        mode: '644',
      }));
      await file.handle.close();
    }
    return Object.freeze({
      uid,
      gid,
      rootDev: rootStat.dev.toString(),
      rootIno: rootStat.ino.toString(),
      rootMode: Number(rootStat.mode & 0o777n).toString(8),
      files: Object.freeze(files),
      totalBytes: total,
      close: async () => { for (const handle of directories.reverse()) await handle.close().catch(() => {}); },
    });
  } catch (error) {
    for (const handle of directories.reverse()) await handle.close().catch(() => {});
    if (error instanceof DispatchError) throw error;
    fail('source-closure-unavailable');
  }
}

async function verifyCheckoutHead(workspace, expectedCommit, uid = process.getuid(), gid = process.getgid()) {
  const gitPath = path.join(workspace, '.git');
  let gitHandle;
  let headHandle;
  try {
    const gitNamed = await fs.lstat(gitPath, { bigint: true });
    gitHandle = await fs.open(gitPath, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC);
    const gitStat = await gitHandle.stat({ bigint: true });
    ensureDirectoryStat(gitStat, uid, gid, 0o755);
    if (fileIdentity(gitStat) !== fileIdentity(gitNamed)) fail('source-git-directory-changed');
    const headPath = `/proc/self/fd/${gitHandle.fd}/HEAD`;
    const headNamed = await fs.lstat(headPath, { bigint: true });
    headHandle = await fs.open(headPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC);
    const headStat = await headHandle.stat({ bigint: true });
    if (!headStat.isFile() || headStat.uid !== BigInt(uid) || headStat.gid !== BigInt(gid) || headStat.nlink !== 1n
        || (headStat.mode & 0o022n) !== 0n || Number(headStat.mode & 0o777n) !== 0o644
        || headStat.size !== 41n || fileIdentity(headStat) !== fileIdentity(headNamed)) fail('source-git-head-refused');
    const head = await headHandle.readFile('utf8');
    if (head !== `${expectedCommit}\n`) fail('source-git-head-mismatch');
    if (fileIdentity(headStat) !== fileIdentity(await headHandle.stat({ bigint: true }))) fail('source-git-head-changed');
  } catch (error) {
    if (error instanceof DispatchError) throw error;
    fail('source-git-metadata-unavailable');
  } finally {
    await headHandle?.close().catch(() => {});
    await gitHandle?.close().catch(() => {});
  }
}

async function fixedSourceCheckout(workspaceValue) {
  if (typeof workspaceValue !== 'string' || !path.isAbsolute(workspaceValue)
      || path.resolve(workspaceValue) !== workspaceValue) fail('invalid-workspace-path');
  let workspace;
  let initialCwd;
  try {
    workspace = await fs.realpath(workspaceValue);
    initialCwd = await fs.realpath(process.cwd());
  } catch { fail('source-workspace-unavailable'); }
  if (workspace !== workspaceValue || initialCwd !== workspace) fail('source-cwd-mismatch');
  const sourceWorkspace = path.join(workspace, SOURCE_CHECKOUT_RELATIVE);
  let canonical;
  try { canonical = await fs.realpath(sourceWorkspace); } catch { fail('source-checkout-unavailable'); }
  if (canonical !== sourceWorkspace) fail('source-checkout-path-refused');
  try { process.chdir(sourceWorkspace); } catch { fail('source-checkout-unavailable'); }
  return sourceWorkspace;
}

async function verifySourceSnapshot(workspace, snapshot) {
  let root;
  try {
    root = await fs.open(workspace, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC);
    const stat = await root.stat({ bigint: true });
    if (stat.dev.toString() !== snapshot.rootDev || stat.ino.toString() !== snapshot.rootIno
        || stat.uid.toString() !== String(snapshot.uid) || stat.gid.toString() !== String(snapshot.gid)
        || Number(stat.mode & 0o777n).toString(8) !== snapshot.rootMode) fail('source-workspace-changed');
  } catch (error) {
    if (error instanceof DispatchError) throw error;
    fail('source-workspace-changed');
  } finally {
    await root?.close().catch(() => {});
  }
  const reread = await inspectSources(workspace, {
    files: Object.freeze(Object.fromEntries(snapshot.files.map((file) => [file.destination, file.digest]))),
  });
  try {
    if (reread.totalBytes !== snapshot.totalBytes || reread.files.length !== snapshot.files.length
        || reread.files.some((file, index) => fileIdentityFromRow(file) !== fileIdentityFromRow(snapshot.files[index]))) fail('source-closure-changed');
  } finally {
    await reread.close();
  }
}

function fileIdentityFromRow(value) {
  return [value.destination, value.sourceRelative, value.digest, value.size, value.dev, value.ino, value.uid, value.gid, value.mode].join(':');
}

function validateRuntimeUrl(raw, name) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 2048 || !/^[\x21-\x7e]+$/u.test(raw)) fail(`${name}-unavailable`);
  let url;
  try { url = new URL(raw); } catch { fail(`${name}-unavailable`); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.hash) fail(`${name}-unavailable`);
  return raw;
}

function verifyRuntimeCredentials(runtime) {
  if (!exactKeys(runtime, ['ACTIONS_RUNTIME_TOKEN', 'ACTIONS_RESULTS_URL', 'ACTIONS_RUNTIME_URL'])) fail('runtime-credential-unavailable');
  const token = runtime.ACTIONS_RUNTIME_TOKEN;
  if (typeof token !== 'string' || token.length < 1 || Buffer.byteLength(token, 'utf8') > 8192
      || !/^[\x21-\x7e]+$/u.test(token)) fail('runtime-credential-unavailable');
  validateRuntimeUrl(runtime.ACTIONS_RUNTIME_URL, 'runtime-url');
  validateRuntimeUrl(runtime.ACTIONS_RESULTS_URL, 'results-url');
}

function remainingJobNanoseconds(startedAtMs, nowMs = Date.now()) {
  if (!Number.isFinite(startedAtMs) || startedAtMs <= 0 || !Number.isFinite(nowMs)) fail('job-start-unavailable');
  const remainingMs = startedAtMs + 600_000 - nowMs;
  if (!Number.isFinite(remainingMs)) fail('job-start-unavailable');
  return BigInt(Math.floor(remainingMs * 1_000_000));
}

function apiUrl(pathname) {
  const url = new URL(pathname, `${API_ROOT}/`);
  if (url.origin !== API_ROOT || url.username || url.password || url.hash) fail('github-api-url-invalid');
  return url;
}

async function boundedResponse(response, maxBytes) {
  if (response.status !== 200 || !response.body) fail('github-metadata-refused');
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^(?:0|[1-9][0-9]*)$/u.test(declared) || Number(declared) > maxBytes)) fail('github-metadata-too-large');
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        fail('github-metadata-too-large');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

async function githubJson(pathname, token, metadataDeadlineNs) {
  const remaining = metadataDeadlineNs - process.hrtime.bigint();
  if (remaining <= 0n) fail('github-metadata-timeout');
  const timeoutMs = Math.max(1, Math.min(3000, Number(remaining / 1_000_000n)));
  let response;
  try {
    response = await fetch(apiUrl(pathname), {
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'dotunnel-fixed-runner-dispatch',
      },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    fail('github-metadata-unavailable');
  }
  if (response.headers.has('link') && /rel="next"/u.test(response.headers.get('link') ?? '')) fail('github-metadata-pagination');
  const raw = await boundedResponse(response, MAX_GITHUB_RESPONSE_BYTES);
  const contentType = response.headers.get('content-type') ?? '';
  if (!/^application\/json\b/iu.test(contentType)) fail('github-metadata-content-type');
  return parseStrictJson(raw, MAX_GITHUB_RESPONSE_BYTES);
}

function verifyChecks(checks) {
  if (!isRecord(checks) || !Array.isArray(checks.check_runs) || checks.check_runs.length > 100
      || checks.total_count !== checks.check_runs.length) fail('source-ci-metadata-invalid');
  for (const name of REQUIRED_CHECKS) {
    const matching = checks.check_runs.filter((row) => isRecord(row) && row.name === name && isRecord(row.app) && row.app.id === CHECK_APP_ID);
    if (matching.length !== 1) fail('source-ci-required-check-unavailable');
    const [check] = matching;
    if (check.status !== 'completed' || check.conclusion !== 'success') fail('source-ci-required-check-not-passing');
  }
}

function strictIsoTimestamp(value) {
  const match = typeof value === 'string'
    ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/u.exec(value)
    : null;
  if (!match) fail('job-start-unavailable');
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) fail('job-start-unavailable');
  const date = new Date(parsed);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() + 1 !== month || date.getUTCDate() !== day
      || date.getUTCHours() !== hour || date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second) fail('job-start-unavailable');
  return parsed;
}

export function comparisonIsAncestor(value, helperCommit, workflowCommit) {
  return isRecord(value) && ['identical', 'ahead'].includes(value.status)
    && isRecord(value.base_commit) && value.base_commit.sha === helperCommit
    && isRecord(value.merge_base_commit) && value.merge_base_commit.sha === helperCommit
    && value.url === `${API_ROOT}/repos/${REPOSITORY}/compare/${helperCommit}...${workflowCommit}`
    && Number.isSafeInteger(value.ahead_by) && value.ahead_by >= 0;
}

async function verifyGitHubMetadata(invocation, manifest, env) {
  const token = env.GITHUB_TOKEN;
  if (typeof token !== 'string' || token.length < 1 || Buffer.byteLength(token, 'utf8') > 8192
      || !/^[\x21-\x7e]+$/u.test(token)) fail('github-read-token-unavailable');
  const apiUrlEnv = env.GITHUB_API_URL;
  if (typeof apiUrlEnv !== 'string' || Buffer.byteLength(apiUrlEnv, 'utf8') > 2048
      || !/^[\x21-\x7e]+$/u.test(apiUrlEnv)) fail('github-api-url-unavailable');
  let suppliedApi;
  try { suppliedApi = new URL(apiUrlEnv); } catch { fail('github-api-url-unavailable'); }
  if (suppliedApi.origin !== API_ROOT || !['', '/'].includes(suppliedApi.pathname)
      || suppliedApi.search || suppliedApi.hash || suppliedApi.username || suppliedApi.password) fail('github-api-url-unavailable');
  const metadataDeadlineNs = process.hrtime.bigint() + 20_000_000_000n;
  const repoPath = '/repos/junited31/dotunnel';
  const [branch, workflowChecks, helperChecks, comparison, jobs] = await Promise.all([
    githubJson(`${repoPath}/branches/main`, token, metadataDeadlineNs),
    githubJson(`${repoPath}/commits/${invocation.sourceCommit}/check-runs?per_page=100`, token, metadataDeadlineNs),
    githubJson(`${repoPath}/commits/${manifest.commit}/check-runs?per_page=100`, token, metadataDeadlineNs),
    githubJson(`${repoPath}/compare/${manifest.commit}...${invocation.sourceCommit}`, token, metadataDeadlineNs),
    githubJson(`${repoPath}/actions/runs/${invocation.names.run}/attempts/${invocation.names.attempt}/jobs?per_page=100`, token, metadataDeadlineNs),
  ]);
  if (!isRecord(branch) || branch.protected !== true || !isRecord(branch.commit)
      || branch.commit.sha !== invocation.sourceCommit) fail('main-source-mismatch');
  verifyChecks(workflowChecks);
  verifyChecks(helperChecks);
  if (!comparisonIsAncestor(comparison, manifest.commit, invocation.sourceCommit)) fail('bootstrap-not-on-main');
  if (!isRecord(jobs) || !Array.isArray(jobs.jobs) || jobs.jobs.length > 100 || jobs.total_count !== jobs.jobs.length) fail('job-metadata-invalid');
  const currentJobs = jobs.jobs.filter((job) => isRecord(job) && job.name === invocation.job);
  if (currentJobs.length !== 1) fail('job-metadata-ambiguous');
  const [job] = currentJobs;
  if (job.status !== 'in_progress' || job.conclusion !== null || job.head_sha !== invocation.sourceCommit
      || String(job.run_attempt) !== invocation.names.attempt) fail('job-metadata-mismatch');
  const startedAtMs = strictIsoTimestamp(job.started_at);
  return Object.freeze({ startedAtMs });
}

function rootChildEnvironment() {
  return { ...ROOT_CHILD_ENV };
}

function exactRootChildEnv() {
  return rootChildEnvironment();
}

function rootFilesystemPaths(names) {
  return [names.root, names.control, names.source, names.sourceTemp, names.stage, names.native];
}

async function assertAbsent(pathname) {
  try {
    await fs.lstat(pathname);
    fail('runner-resource-collision');
  } catch (error) {
    if (error instanceof DispatchError) throw error;
    if (error?.code !== 'ENOENT') fail('runner-resource-collision');
  }
}

export function trustedNodeStat(stat) {
  return stat.isFile() && stat.uid === 0n && stat.nlink === 1n
    && (stat.mode & 0o022n) === 0n && (stat.mode & 0o111n) !== 0n;
}

async function verifyNodeRuntime() {
  if (typeof process.versions.node !== 'string' || !/^24\./u.test(process.versions.node)) fail('node-runtime-version-refused');
  let actualPath;
  let configuredPath;
  let stat;
  try {
    actualPath = await fs.realpath('/proc/self/exe');
    configuredPath = await fs.realpath(process.execPath);
    stat = await fs.stat('/proc/self/exe', { bigint: true });
  } catch { fail('node-runtime-identity-unavailable'); }
  if (actualPath !== configuredPath || !trustedNodeStat(stat)) fail('node-runtime-identity-refused');
}

async function secureBinary(pathname, { requireSetuid = false } = {}) {
  let stat;
  let canonical;
  try {
    stat = await fs.lstat(pathname, { bigint: true });
    canonical = await fs.realpath(pathname);
  } catch { fail('secure-native-binary-unavailable'); }
  if (!stat.isFile() || stat.uid !== 0n || stat.nlink !== 1n || (stat.mode & 0o022n) !== 0n
      || (stat.mode & 0o111n) === 0n || (requireSetuid && (stat.mode & 0o4000n) === 0n)
      || canonical !== pathname) fail('secure-native-binary-refused');
}

async function checkNativeBinaries() {
  for (const pathname of FIXED_NATIVE_BINARIES) {
    await secureBinary(pathname, { requireSetuid: pathname === '/usr/bin/sudo' });
  }
  let pythonPath;
  try { pythonPath = await fs.realpath(ROOT_PYTHON); } catch { fail('secure-root-python-unavailable'); }
  if (!pythonPath.startsWith('/usr/bin/')) fail('secure-root-python-refused');
  const pythonStat = await fs.stat(pythonPath, { bigint: true });
  if (!pythonStat.isFile() || pythonStat.uid !== 0n || pythonStat.nlink !== 1n || (pythonStat.mode & 0o022n) !== 0n
      || (pythonStat.mode & 0o111n) === 0n) fail('secure-root-python-refused');
}

function checkedClosure(manifest) {
  const payload = {
    commit: manifest.commit,
    files: Object.fromEntries(Object.keys(manifest.files).sort().map((name) => [name, manifest.files[name]])),
    upload_action_commit: manifest.upload_action_commit,
  };
  const closureSha256 = createHash('sha256').update(canonicalJson(payload), 'ascii').digest('hex');
  const sourceManifest = {
    schema: 1,
    commit: manifest.commit,
    files: payload.files,
    upload_action_commit: manifest.upload_action_commit,
    closure_sha256: closureSha256,
  };
  const sourceManifestBytes = Buffer.from(canonicalJson(sourceManifest), 'ascii');
  if (sourceManifestBytes.length > MAX_MANIFEST_BYTES) fail('root-source-manifest-too-large');
  return Object.freeze({ payload, closureSha256, sourceManifestBytes });
}

function filesTsv(snapshot) {
  return snapshot.files.map((file) => [
    file.destination,
    file.sourceRelative,
    file.digest,
    String(file.size),
    file.dev,
    file.ino,
    file.uid,
    file.gid,
    file.mode,
  ].join('\t')).join('\n') + '\n';
}


function shellLiteral(strings) {
  if (!Array.isArray(strings.raw) || strings.length !== 1) fail('invalid-native-script-template');
  return strings.raw[0].replaceAll('\\${', '${');
}

const BOOTSTRAP_SCRIPT = shellLiteral`
set -Eeuo pipefail
umask 077
exec {payload_fd}<&0
exec </dev/null
unset BASH_ENV ENV GH_TOKEN GH_ENTERPRISE_TOKEN GITHUB_TOKEN GITHUB_OUTPUT GITHUB_WORKSPACE GITHUB_SHA GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_REPOSITORY GITHUB_REF GITHUB_EVENT_NAME GITHUB_ACTOR GITHUB_TRIGGERING_ACTOR GITHUB_JOB GITHUB_API_URL GITHUB_SERVER_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL ACTIONS_RESULTS_URL ACTIONS_CACHE_URL DOTUNNEL_BOOTSTRAP_MANIFEST DOTUNNEL_SOURCE_DEV DOTUNNEL_SOURCE_INO DOTUNNEL_RECEIPT_SCENARIO HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY NODE_OPTIONS NODE_PATH
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
run="$1"
attempt="$2"
dispatcher_pid="$3"
dispatcher_birth="$4"
runner_uid="$5"
runner_gid="$6"
source_dev="$7"
source_ino="$8"
source_mode="$9"
manifest_b64="\${10}"
files_b64="\${11}"
expected_bootstrap_nonce="\${12}"
[[ "$EUID" -eq 0 && "$run" =~ ^[1-9][0-9]{0,19}$ && "$attempt" =~ ^[1-9][0-9]{0,19}$ ]]
[[ "$dispatcher_pid" =~ ^[1-9][0-9]{0,9}$ && "$dispatcher_birth" =~ ^[1-9][0-9]{0,19}$ ]]
[[ "$runner_uid" =~ ^[1-9][0-9]{0,9}$ && "$runner_gid" =~ ^[0-9]{1,9}$ ]]
[[ "$source_dev" =~ ^[0-9]{1,20}$ && "$source_ino" =~ ^[1-9][0-9]{0,20}$ && "$source_mode" == 755 ]]
[[ "$expected_bootstrap_nonce" =~ ^[0-9a-f]{32}$ ]]
[[ "\${DOTUNNEL_BOOTSTRAP_NONCE-}" == "$expected_bootstrap_nonce" ]]
native_uuid="$(</proc/sys/kernel/random/uuid)"
native_nonce="\${native_uuid//-/}"
[[ "$native_nonce" =~ ^[0-9a-f]{32}$ ]]
prefix="dotunnelpilot\${run}a\${attempt}"
root="/run/\${prefix}"
source_root="\${root}-source"
source_tmp="\${root}-source-tmp"
stage="\${root}-stage"
native="\${root}-native"
recovery_unit="dotunnelbootstraprecovery\${run}a\${attempt}.service"
recovery_file="/run/systemd/system/\${recovery_unit}"
bootstrap_unit="\${prefix}-bootstrap.service"
bootstrap_cgroup="$(/usr/bin/systemctl show --property=ControlGroup --value "$bootstrap_unit")"
[[ "$(/usr/bin/systemctl show --property=MainPID --value "$bootstrap_unit")" == "$$" ]]
[[ "$bootstrap_cgroup" == "/system.slice/$bootstrap_unit" ]]
[[ "$(< /proc/self/cgroup)" == "0::$bootstrap_cgroup" ]]
[[ "$(/usr/bin/systemctl show --property=InvocationID --value "$bootstrap_unit")" =~ ^[0-9a-f]{32}$ ]]
[[ "$(/usr/bin/systemctl show --property=KillMode --value "$bootstrap_unit")" == control-group ]]
[[ "$(/usr/bin/systemctl show --property=OOMPolicy --value "$bootstrap_unit")" == kill ]]
[[ "$(/usr/bin/systemctl show --property=TimeoutStopUSec --value "$bootstrap_unit")" == 2s ]]
bootstrap_lifetime="$(/usr/bin/systemctl show --property=RuntimeMaxUSec --value "$bootstrap_unit")"
[[ "$bootstrap_lifetime" == '1min 30s' || "$bootstrap_lifetime" == 90s ]]
bootstrap_cgroup_path="/sys/fs/cgroup$bootstrap_cgroup"
[[ ! -L "$bootstrap_cgroup_path" && -d "$bootstrap_cgroup_path" ]]
[[ "$(< "$bootstrap_cgroup_path/memory.max")" == 805306368 ]]
[[ "$(< "$bootstrap_cgroup_path/memory.swap.max")" == 0 ]]
[[ "$(< "$bootstrap_cgroup_path/pids.max")" == 128 ]]
[[ "$(< "$bootstrap_cgroup_path/memory.oom.group")" == 1 ]]
read -r bootstrap_quota bootstrap_period < "$bootstrap_cgroup_path/cpu.max"
[[ "$bootstrap_quota" =~ ^[1-9][0-9]{0,6}$ && "$bootstrap_period" =~ ^[1-9][0-9]{0,6}$ ]]
[[ "$bootstrap_quota" == "$bootstrap_period" ]]
[[ "$(/usr/bin/stat -Lc '%u %g %a' /run)" == '0 0 755' ]]
[[ "$(/usr/bin/stat -Lc '%u %g %a' /run/systemd/system)" == '0 0 755' ]]
[[ "$(/usr/bin/stat -Lc '%u:%g:%a:%d:%i' .)" == "\${runner_uid}:\${runner_gid}:\${source_mode}:\${source_dev}:\${source_ino}" ]]
proc_stat="$(</proc/\${dispatcher_pid}/stat)"
proc_rest="\${proc_stat##*) }"
read -r -a proc_fields <<< "$proc_rest"
[[ "\${proc_fields[19]-}" == "$dispatcher_birth" ]]
[[ "$(/usr/bin/stat -Lc '%u' "/proc/\${dispatcher_pid}")" == "$runner_uid" ]]
[[ ! -e "$root" && ! -L "$root" && ! -e "\${root}-control" && ! -L "\${root}-control" ]]
[[ ! -e "$source_root" && ! -L "$source_root" && ! -e "$source_tmp" && ! -L "$source_tmp" && ! -e "$stage" && ! -L "$stage" ]]
[[ ! -e "$native" && ! -L "$native" && ! -e "$recovery_file" && ! -L "$recovery_file" ]]
/usr/bin/mkdir -m 700 -- "$native"
read -r native_uid native_mode native_dev native_ino < <(/usr/bin/stat -Lc '%u %a %d %i' "$native")
[[ "$native_uid" == 0 && "$native_mode" == 700 ]]
printf '%s %s %s\n' "$native_dev" "$native_ino" "$native_nonce" > "$native/native.identity"
/usr/bin/sync -f "$native/native.identity"
source_parent_devino="$(/usr/bin/stat -Lc '%d:%i' /run)"
printf '%s %s %s\n' "\${source_parent_devino%:*}" "\${source_parent_devino#*:}" "$native_nonce" > "$native/source.intent"
/usr/bin/sync -f "$native/source.intent"
/usr/bin/base64 -d <<< "$files_b64" > "$native/files.tsv"
/usr/bin/base64 -d <<< "$manifest_b64" > "$native/manifest.json"
/usr/bin/chmod 600 "$native/files.tsv" "$native/manifest.json"
files_table_size="$(/usr/bin/stat -Lc '%s' "$native/files.tsv")"
[[ "$(/usr/bin/stat -Lc '%u %g %h %a' "$native/files.tsv")" == '0 0 1 600' ]]
[[ "$files_table_size" =~ ^[1-9][0-9]{0,3}$ && "$files_table_size" -le 8192 ]]
[[ "$(/usr/bin/stat -Lc '%u %g %h %a' "$native/manifest.json")" == '0 0 1 600' ]]
manifest_size="$(/usr/bin/stat -Lc '%s' "$native/manifest.json")"
[[ "$manifest_size" =~ ^[1-9][0-9]{0,3}$ && "$manifest_size" -le 4096 ]]
/usr/bin/cat > "$native/recover.sh" <<'RECOVERY_SCRIPT'
set -Eeuo pipefail
umask 077
exec </dev/null
run="$1"
attempt="$2"
prefix="dotunnelpilot\${run}a\${attempt}"
stage="/run/\${prefix}-stage"
source_root="/run/\${prefix}-source"
source_tmp="/run/\${prefix}-source-tmp"
native="/run/\${prefix}-native"
[[ "$EUID" -eq 0 && "$run" =~ ^[1-9][0-9]{0,19}$ && "$attempt" =~ ^[1-9][0-9]{0,19}$ ]]
[[ -d "$native" && ! -L "$native" && "$(/usr/bin/stat -Lc '%u %a' "$native")" == '0 700' ]]
read -r owner_uid owner_mode owner_dev owner_ino < <(/usr/bin/stat -Lc '%u %a %d %i' "$native")
read -r recorded_native_dev recorded_native_ino nonce < "$native/native.identity"
[[ "$recorded_native_dev:$recorded_native_ino" == "$owner_dev:$owner_ino" && "$nonce" =~ ^[0-9a-f]{32}$ ]]
[[ -f "$native/stage.intent" && ! -L "$native/stage.intent" ]]
read -r stage_parent_dev stage_parent_ino recorded_nonce < "$native/stage.intent"
[[ "$recorded_nonce" == "$nonce" && "$stage_parent_dev" =~ ^[0-9]{1,20}$ && "$stage_parent_ino" =~ ^[1-9][0-9]{0,20}$ ]]
[[ "$(/usr/bin/stat -Lc '%d:%i' /run)" == "$stage_parent_dev:$stage_parent_ino" ]]
mount_count=0
mount_id=''
mount_device=''
mount_flags=''
mount_super=''
while IFS= read -r line; do
  before="\${line%% - *}"
  after="\${line#* - }"
  read -r -a left_fields <<< "$before"
  read -r -a right_fields <<< "$after"
  if [[ "\${left_fields[4]-}" == "$stage" ]]; then
    mount_count=$((mount_count + 1))
    mount_id="\${left_fields[0]}"
    mount_device="\${left_fields[2]}"
    mount_flags="\${left_fields[5]}"
    mount_super="\${right_fields[2]-}"
    [[ "\${right_fields[0]-}" == tmpfs && "\${right_fields[1]-}" == "dotunnel-stage-$nonce" ]]
  elif [[ "\${left_fields[4]-}" == "$stage/"* ]]; then
    exit 1
  fi
done < /proc/self/mountinfo
[[ "$mount_count" -le 1 ]]
if [[ "$mount_count" -eq 1 ]]; then
  [[ "$mount_id" =~ ^[1-9][0-9]*$ && "$mount_device" =~ ^[0-9]+:[0-9]+$ ]]
  case ",$mount_flags," in *,rw,*) ;; *) exit 1;; esac
  case ",$mount_flags," in *,nodev,*) ;; *) exit 1;; esac
  case ",$mount_flags," in *,nosuid,*) ;; *) exit 1;; esac
  case ",$mount_flags," in *,noexec,*) ;; *) exit 1;; esac
  case ",$mount_super," in *,rw,*) ;; *) exit 1;; esac
  case ",$mount_super," in *,nr_inodes=128,*) ;; *) exit 1;; esac
  case ",$mount_super," in *,size=16384k,*|*,size=16m,*) ;; *) exit 1;; esac
  [[ -f "$native/stage.dir" && ! -L "$native/stage.dir" ]]
  read -r stage_dir_dev stage_dir_ino stage_dir_nonce < "$native/stage.dir"
  [[ "$stage_dir_nonce" == "$nonce" && "$stage_dir_dev" =~ ^[0-9]{1,20}$ && "$stage_dir_ino" =~ ^[1-9][0-9]{0,20}$ ]]
  current_devino="$(/usr/bin/stat -Lc '%d:%i' "$stage")"
  if [[ -e "$native/stage.identity" || -L "$native/stage.identity" ]]; then
    [[ -f "$native/stage.identity" && ! -L "$native/stage.identity" ]]
    read -r expected_id expected_mount_device expected_dev expected_ino expected_nonce < "$native/stage.identity"
    [[ "$expected_id" == "$mount_id" && "$expected_mount_device" == "$mount_device"
        && "$expected_dev:$expected_ino" == "$current_devino" && "$expected_nonce" == "$nonce" ]]
  fi
  [[ "$(/usr/bin/stat -Lc '%u %g %a' "$stage")" == '0 0 700' ]]
  /usr/bin/umount -- "$stage"
  remaining_mounts=0
  while IFS= read -r line; do
    before="\${line%% - *}"
    read -r -a left_fields <<< "$before"
    if [[ "\${left_fields[4]-}" == "$stage" || "\${left_fields[4]-}" == "$stage/"* ]]; then
      remaining_mounts=$((remaining_mounts + 1))
    fi
  done < /proc/self/mountinfo
  [[ "$remaining_mounts" -eq 0 ]]
fi
if [[ -e "$stage" || -L "$stage" ]]; then
  [[ -d "$stage" && ! -L "$stage" && "$(/usr/bin/stat -Lc '%u %a' "$stage")" == '0 700' ]]
  if [[ -f "$native/stage.dir" && ! -L "$native/stage.dir" ]]; then
    read -r stage_dir_dev stage_dir_ino stage_dir_nonce < "$native/stage.dir"
    [[ "$stage_dir_nonce" == "$nonce" && "$(/usr/bin/stat -Lc '%d:%i' "$stage")" == "$stage_dir_dev:$stage_dir_ino" ]]
  else
    [[ "$mount_count" -eq 0 ]]
  fi
  /usr/bin/rmdir -- "$stage"
elif [[ "$mount_count" -eq 1 ]]; then
  exit 1
fi
[[ -f "$native/source.intent" && ! -L "$native/source.intent" ]]
read -r source_parent_dev source_parent_ino source_intent_nonce < "$native/source.intent"
[[ "$source_intent_nonce" == "$nonce" && "$source_parent_dev" =~ ^[0-9]{1,20}$ && "$source_parent_ino" =~ ^[1-9][0-9]{0,20}$ ]]
[[ "$(/usr/bin/stat -Lc '%d:%i' /run)" == "$source_parent_dev:$source_parent_ino" ]]
if [[ -e "$source_tmp" || -L "$source_tmp" ]]; then
  [[ -d "$source_tmp" && ! -L "$source_tmp" ]]
  if [[ -f "$native/source.dir" && ! -L "$native/source.dir" ]]; then
    read -r source_dir_dev source_dir_ino source_dir_nonce < "$native/source.dir"
    [[ "$source_dir_nonce" == "$nonce" && "$source_dir_dev" =~ ^[0-9]{1,20}$ && "$source_dir_ino" =~ ^[1-9][0-9]{0,20}$ ]]
    [[ "$(/usr/bin/stat -Lc '%d:%i %u' "$source_tmp")" == "$source_dir_dev:$source_dir_ino 0" ]]
  else
    [[ "$(/usr/bin/stat -Lc '%u %a' "$source_tmp")" == '0 700' ]]
    /usr/bin/rmdir -- "$source_tmp"
  fi
  if [[ -e "$source_tmp" ]]; then
    if [[ -f "$native/source.ready" && ! -L "$native/source.ready" ]]; then
      read -r ready_dev ready_ino ready_nonce < "$native/source.ready"
      [[ "$ready_nonce" == "$nonce" && "$ready_dev:$ready_ino" == "$source_dir_dev:$source_dir_ino" ]]
      [[ "$(/usr/bin/stat -Lc '%u %a' "$source_tmp")" == '0 500' ]]
      file_total=0
      file_count=0
      while IFS=$'\t' read -r destination relative digest expected_size expected_dev expected_ino expected_uid expected_gid expected_mode; do
        case "$destination:$relative" in
          runner_prepare.py:tools/release_verify/runner_prepare.py|runner_policy.py:tools/release_verify/runner_policy.py|runner_runtime.py:tools/release_verify/runner_runtime.py|runner_artifact.py:tools/release_verify/runner_artifact.py|runner_dispatch.mjs:tools/release_verify/runner_dispatch.mjs|upload-index.js:.verification-upload-action/dist/upload/index.js|upload-action.yml:.verification-upload-action/action.yml|package-lock.json:.verification-upload-action/package-lock.json) ;;
          *) exit 1;;
        esac
        [[ "$digest" =~ ^[0-9a-f]{64}$ && "$expected_size" =~ ^[1-9][0-9]{0,8}$ ]]
        if [[ "$destination" == upload-index.js ]]; then limit=12582912; else limit=1048576; fi
        [[ "$expected_size" -le "$limit" ]]
        file_total=$((file_total + expected_size))
        file_count=$((file_count + 1))
        [[ "$file_total" -le 16777216 && "$file_count" -le 8 ]]
        [[ -f "$source_tmp/$destination" && ! -L "$source_tmp/$destination" ]]
        [[ "$(/usr/bin/stat -Lc '%u %g %h %a %s' "$source_tmp/$destination")" == "0 0 1 400 $expected_size" ]]
        [[ "$(/usr/bin/sha256sum -- "$source_tmp/$destination" | { read -r value _; printf '%s' "$value"; })" == "$digest" ]]
      done < "$native/files.tsv"
      [[ "$file_count" -ge 6 ]]
      [[ -f "$source_tmp/manifest.json" && ! -L "$source_tmp/manifest.json" ]]
      [[ "$(/usr/bin/stat -Lc '%u %g %h %a %s' "$source_tmp/manifest.json")" =~ ^0\ 0\ 1\ 400\ [1-9][0-9]{0,3}$ ]]
      [[ "$(/usr/bin/stat -Lc '%s' "$source_tmp/manifest.json")" -le 4096 ]]
      native_manifest_hash="$(/usr/bin/sha256sum -- "$native/manifest.json" | { read -r value _; printf '%s' "$value"; })"
      source_manifest_hash="$(/usr/bin/sha256sum -- "$source_tmp/manifest.json" | { read -r value _; printf '%s' "$value"; })"
      [[ "$native_manifest_hash" == "$source_manifest_hash" ]]
      [[ "$(/usr/bin/stat -Lc '%d' /run)" == "$(/usr/bin/stat -Lc '%d' "$source_tmp")" ]]
      [[ ! -e "$source_root" && ! -L "$source_root" ]]
      /usr/bin/mv -T --no-clobber -- "$source_tmp" "$source_root"
      [[ ! -e "$source_tmp" && ! -L "$source_tmp" ]]
      [[ "$(/usr/bin/stat -Lc '%d:%i %u %a' "$source_root")" == "$source_dir_dev:$source_dir_ino 0 500" ]]
    else
      source_partial_mode="$(/usr/bin/stat -Lc '%u %a' "$source_tmp")"
      [[ "$source_partial_mode" == '0 700' || "$source_partial_mode" == '0 500' ]]
      /usr/bin/chmod 700 -- "$source_tmp"
      while IFS=$'\t' read -r destination relative digest expected_size expected_dev expected_ino expected_uid expected_gid expected_mode; do
        case "$destination:$relative" in
          runner_prepare.py:tools/release_verify/runner_prepare.py|runner_policy.py:tools/release_verify/runner_policy.py|runner_runtime.py:tools/release_verify/runner_runtime.py|runner_artifact.py:tools/release_verify/runner_artifact.py|runner_dispatch.mjs:tools/release_verify/runner_dispatch.mjs|upload-index.js:.verification-upload-action/dist/upload/index.js|upload-action.yml:.verification-upload-action/action.yml|package-lock.json:.verification-upload-action/package-lock.json) ;;
          *) exit 1;;
        esac
        candidate="$source_tmp/$destination"
        if [[ -e "$candidate" || -L "$candidate" ]]; then
          [[ -f "$candidate" && ! -L "$candidate" ]]
          read -r candidate_uid candidate_gid candidate_links candidate_mode candidate_size < <(/usr/bin/stat -Lc '%u %g %h %a %s' "$candidate")
          if [[ "$destination" == upload-index.js ]]; then limit=12582912; else limit=1048576; fi
          [[ "$candidate_uid" == 0 && "$candidate_gid" == 0 && "$candidate_links" == 1
              && ( "$candidate_mode" == 600 || "$candidate_mode" == 400 )
              && "$candidate_size" =~ ^[0-9]{1,9}$ && "$candidate_size" -le "$limit" ]]
          /usr/bin/rm -- "$candidate"
        fi
      done < "$native/files.tsv"
      candidate="$source_tmp/manifest.json"
      if [[ -e "$candidate" || -L "$candidate" ]]; then
        [[ -f "$candidate" && ! -L "$candidate" ]]
        read -r candidate_uid candidate_gid candidate_links candidate_mode candidate_size < <(/usr/bin/stat -Lc '%u %g %h %a %s' "$candidate")
        [[ "$candidate_uid" == 0 && "$candidate_gid" == 0 && "$candidate_links" == 1
            && ( "$candidate_mode" == 600 || "$candidate_mode" == 400 )
            && "$candidate_size" =~ ^[0-9]{1,4}$ && "$candidate_size" -le 4096 ]]
        /usr/bin/rm -- "$candidate"
      fi
      /usr/bin/rmdir -- "$source_tmp"
    fi
  fi
fi
RECOVERY_SCRIPT
/usr/bin/chmod 400 "$native/recover.sh"
stage_parent_devino="$(/usr/bin/stat -Lc '%d:%i' /run)"
printf '%s %s %s\n' "\${stage_parent_devino%:*}" "\${stage_parent_devino#*:}" "$native_nonce" > "$native/stage.intent"
/usr/bin/sync -f "$native/stage.intent"
recovery_tmp="\${recovery_file}.tmp"
[[ ! -e "$recovery_file" && ! -L "$recovery_file" && ! -e "$recovery_tmp" && ! -L "$recovery_tmp" ]]
{
  printf '[Unit]\nDescription=Dotunnel bounded bootstrap stage recovery\n\n[Service]\nType=oneshot\nTimeoutStartSec=30s\nUser=root\nGroup=root\nEnvironment=PATH=/usr/sbin:/usr/bin:/sbin:/bin\nUnsetEnvironment=BASH_ENV ENV GH_TOKEN GH_ENTERPRISE_TOKEN GITHUB_TOKEN GITHUB_OUTPUT GITHUB_WORKSPACE GITHUB_SHA GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_REPOSITORY GITHUB_REF GITHUB_EVENT_NAME GITHUB_ACTOR GITHUB_TRIGGERING_ACTOR GITHUB_JOB GITHUB_API_URL GITHUB_SERVER_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL ACTIONS_RESULTS_URL ACTIONS_CACHE_URL DOTUNNEL_BOOTSTRAP_MANIFEST DOTUNNEL_BOOTSTRAP_NONCE DOTUNNEL_SOURCE_DEV DOTUNNEL_SOURCE_INO DOTUNNEL_RECEIPT_SCENARIO HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY NODE_OPTIONS NODE_PATH\nPrivateMounts=no\nExecStart=/usr/bin/bash /run/%s-native/recover.sh %s %s\nMemoryMax=134217728\nMemorySwapMax=0\nCPUQuota=10%%\nTasksMax=32\nRuntimeMaxSec=30s\nKillMode=control-group\nTimeoutStopSec=2s\nOOMPolicy=kill\nStandardInput=null\nStandardOutput=null\nStandardError=null\nLogRateLimitIntervalSec=1s\nLogRateLimitBurst=1\n' "$prefix" "$run" "$attempt"
} > "$recovery_tmp"
/usr/bin/chmod 644 "$recovery_tmp"
/usr/bin/sync -f "$recovery_tmp"
/usr/bin/mv -T --no-clobber -- "$recovery_tmp" "$recovery_file"
[[ ! -e "$recovery_tmp" && ! -L "$recovery_tmp" ]]
read -r recovery_uid recovery_gid recovery_links recovery_mode recovery_dev recovery_ino < <(/usr/bin/stat -Lc '%u %g %h %a %d %i' "$recovery_file")
[[ "$recovery_uid" == 0 && "$recovery_gid" == 0 && "$recovery_links" == 1 && "$recovery_mode" == 644 ]]
printf '%s %s\n' "$recovery_dev" "$recovery_ino" > "$native/recovery.identity"
/usr/bin/sync -f "$native/recovery.identity"
/usr/bin/sync -f /run/systemd/system
/usr/bin/systemctl daemon-reload
recovery_state="$(/usr/bin/systemctl show --property=LoadState --value "$recovery_unit")"
[[ "$recovery_state" == loaded ]]
[[ "$(/usr/bin/systemctl show --property=FragmentPath --value "$recovery_unit")" == "$recovery_file" ]]
[[ -z "$(/usr/bin/systemctl show --property=DropInPaths --value "$recovery_unit")" ]]
[[ "$(/usr/bin/systemctl show --property=Type --value "$recovery_unit")" == oneshot ]]
[[ "$(/usr/bin/systemctl show --property=MemoryMax --value "$recovery_unit")" == 134217728 ]]
[[ "$(/usr/bin/systemctl show --property=MemorySwapMax --value "$recovery_unit")" == 0 ]]
[[ "$(/usr/bin/systemctl show --property=TasksMax --value "$recovery_unit")" == 32 ]]
[[ "$(/usr/bin/systemctl show --property=CPUQuotaPerSecUSec --value "$recovery_unit")" == 100ms ]]
[[ "$(/usr/bin/systemctl show --property=TimeoutStartUSec --value "$recovery_unit")" == 30s ]]
[[ "$(/usr/bin/systemctl show --property=RuntimeMaxUSec --value "$recovery_unit")" == 30s ]]
[[ "$(/usr/bin/systemctl show --property=TimeoutStopUSec --value "$recovery_unit")" == 2s ]]
[[ "$(/usr/bin/systemctl show --property=KillMode --value "$recovery_unit")" == control-group ]]
[[ "$(/usr/bin/systemctl show --property=OOMPolicy --value "$recovery_unit")" == kill ]]
/usr/bin/mkdir -m 700 -- "$stage"
read -r stage_uid stage_mode stage_dev stage_ino < <(/usr/bin/stat -Lc '%u %a %d %i' "$stage")
[[ "$stage_uid" == 0 && "$stage_mode" == 700 ]]
printf '%s %s %s\n' "$stage_dev" "$stage_ino" "$native_nonce" > "$native/stage.dir.tmp"
/usr/bin/sync -f "$native/stage.dir.tmp"
/usr/bin/mv -T --no-clobber -- "$native/stage.dir.tmp" "$native/stage.dir"
/usr/bin/sync -f "$native"
/usr/bin/mount -t tmpfs -o size=16m,nr_inodes=128,nodev,nosuid,noexec,mode=0700 "dotunnel-stage-$native_nonce" "$stage"
find_stage_mount() {
  local line before after
  local -a left_fields right_fields
  mount_count=0
  mount_id=''
  mount_device=''
  mount_flags=''
  mount_super=''
  while IFS= read -r line; do
    before="\${line%% - *}"
    after="\${line#* - }"
    read -r -a left_fields <<< "$before"
    read -r -a right_fields <<< "$after"
    if [[ "\${left_fields[4]-}" == "$stage" ]]; then
      mount_count=$((mount_count + 1))
      mount_id="\${left_fields[0]}"
      mount_device="\${left_fields[2]}"
      mount_flags="\${left_fields[5]}"
      mount_super="\${right_fields[2]-}"
      [[ "\${right_fields[0]-}" == tmpfs && "\${right_fields[1]-}" == "dotunnel-stage-$native_nonce" ]]
    elif [[ "\${left_fields[4]-}" == "$stage/"* ]]; then
      return 1
    fi
  done < /proc/self/mountinfo
  [[ "$mount_count" -eq 1 && "$mount_id" =~ ^[1-9][0-9]*$ && "$mount_device" =~ ^[0-9]+:[0-9]+$ ]]
  case ",$mount_flags," in *,rw,*) ;; *) return 1;; esac
  case ",$mount_flags," in *,nodev,*) ;; *) return 1;; esac
  case ",$mount_flags," in *,nosuid,*) ;; *) return 1;; esac
  case ",$mount_flags," in *,noexec,*) ;; *) return 1;; esac
  case ",$mount_super," in *,rw,*) ;; *) return 1;; esac
  case ",$mount_super," in *,nr_inodes=128,*) ;; *) return 1;; esac
  case ",$mount_super," in *,size=16384k,*|*,size=16m,*) ;; *) return 1;; esac
}
find_stage_mount
[[ "$(/usr/bin/stat -Lc '%u %g %a' "$stage")" == '0 0 700' ]]
read -r fs_block_size fs_blocks fs_inodes < <(/usr/bin/stat -f -Lc '%S %b %c' "$stage")
[[ "$fs_block_size" =~ ^[1-9][0-9]*$ && "$fs_blocks" =~ ^[1-9][0-9]*$ && "$fs_inodes" == 128 ]]
(( fs_block_size * fs_blocks <= 16777216 ))
stage_devino="$(/usr/bin/stat -Lc '%d:%i' "$stage")"
printf '%s %s %s %s %s\n' "$mount_id" "$mount_device" "\${stage_devino%:*}" "\${stage_devino#*:}" "$native_nonce" > "$native/stage.identity.tmp"
/usr/bin/sync -f "$native/stage.identity.tmp"
/usr/bin/mv -T --no-clobber -- "$native/stage.identity.tmp" "$native/stage.identity"
/usr/bin/sync -f "$native"
file_total=0
file_count=0
while IFS=$'\t' read -r destination relative digest expected_size expected_dev expected_ino expected_uid expected_gid expected_mode; do
  [[ "$destination" =~ ^[a-z][a-z0-9.-]{0,63}$ && "$digest" =~ ^[0-9a-f]{64}$ && "$expected_size" =~ ^[1-9][0-9]{0,7}$ ]]
  case "$destination:$relative" in
    runner_prepare.py:tools/release_verify/runner_prepare.py|runner_policy.py:tools/release_verify/runner_policy.py|runner_runtime.py:tools/release_verify/runner_runtime.py|runner_artifact.py:tools/release_verify/runner_artifact.py|runner_dispatch.mjs:tools/release_verify/runner_dispatch.mjs|upload-index.js:.verification-upload-action/dist/upload/index.js|upload-action.yml:.verification-upload-action/action.yml|package-lock.json:.verification-upload-action/package-lock.json) ;;
    *) exit 1;;
  esac
  [[ "$expected_dev" =~ ^[0-9]{1,20}$ && "$expected_ino" =~ ^[1-9][0-9]{0,20}$ ]]
  [[ "$expected_uid" == "$runner_uid" && "$expected_gid" == "$runner_gid" && "$expected_mode" == 644 ]]
  if [[ "$destination" == upload-index.js ]]; then
    [[ "$expected_size" -le 12582912 ]]
    limit=12582912
  else
    [[ "$expected_size" -le 1048576 ]]
    limit=1048576
  fi
  file_total=$((file_total + expected_size))
  file_count=$((file_count + 1))
  [[ "$file_total" -le 16777216 && "$file_count" -le 8 ]]
  [[ ! -L "$relative" && -f "$relative" ]]
  [[ "$(/usr/bin/stat -Lc '%d %i %u %g %h %a %s' "$relative")" == "$expected_dev $expected_ino $runner_uid $runner_gid 1 644 $expected_size" ]]
  /usr/bin/prlimit --fsize="$limit" -- /usr/bin/timeout --signal=TERM --kill-after=2s 10s /usr/bin/cp -R --no-dereference --reflink=never --no-preserve=mode,ownership,timestamps -- "$relative" "$stage/$destination"
  [[ -f "$stage/$destination" && ! -L "$stage/$destination" ]]
  [[ "$(/usr/bin/stat -Lc '%u %g %h %a %s' "$stage/$destination")" == "0 0 1 600 $expected_size" ]]
  [[ "$(/usr/bin/sha256sum -- "$stage/$destination" | { read -r value _; printf '%s' "$value"; })" == "$digest" ]]
  [[ "$(/usr/bin/stat -Lc '%d %i %u %g %h %a %s' "$relative")" == "$expected_dev $expected_ino $runner_uid $runner_gid 1 644 $expected_size" ]]
done < "$native/files.tsv"
[[ "$file_count" -ge 6 && "$file_total" -le 16777216 ]]
[[ "$(/usr/bin/stat -f -Lc '%c' "$stage")" -le 128 ]]
/usr/bin/mkdir -m 700 -- "$source_tmp"
read -r source_tmp_uid source_tmp_mode source_dir_dev source_dir_ino < <(/usr/bin/stat -Lc '%u %a %d %i' "$source_tmp")
[[ "$source_tmp_uid" == 0 && "$source_tmp_mode" == 700 && "$source_dir_dev" == "\${source_parent_devino%:*}" ]]
printf '%s %s %s\n' "$source_dir_dev" "$source_dir_ino" "$native_nonce" > "$native/source.dir.tmp"
/usr/bin/sync -f "$native/source.dir.tmp"
/usr/bin/mv -T --no-clobber -- "$native/source.dir.tmp" "$native/source.dir"
/usr/bin/sync -f "$native"
source_file_total=0
source_file_count=0
while IFS=$'\t' read -r destination relative digest expected_size expected_dev expected_ino expected_uid expected_gid expected_mode; do
  if [[ "$destination" == upload-index.js ]]; then limit=12582912; else limit=1048576; fi
  /usr/bin/prlimit --fsize="$limit" -- /usr/bin/timeout --signal=TERM --kill-after=2s 10s /usr/bin/cp -R --no-dereference --reflink=never --no-preserve=mode,ownership,timestamps -- "$stage/$destination" "$source_tmp/$destination"
  [[ -f "$source_tmp/$destination" && ! -L "$source_tmp/$destination" ]]
  [[ "$(/usr/bin/stat -Lc '%u %g %h %a %s' "$source_tmp/$destination")" == "0 0 1 600 $expected_size" ]]
  [[ "$(/usr/bin/sha256sum -- "$source_tmp/$destination" | { read -r value _; printf '%s' "$value"; })" == "$digest" ]]
  source_file_total=$((source_file_total + expected_size))
  source_file_count=$((source_file_count + 1))
  [[ "$source_file_total" -le 16777216 && "$source_file_count" -le 8 ]]
done < "$native/files.tsv"
[[ "$source_file_count" -eq "$file_count" && "$source_file_total" -eq "$file_total" ]]
/usr/bin/base64 -d <<< "$manifest_b64" > "$source_tmp/manifest.json"
manifest_size="$(/usr/bin/stat -Lc '%s' "$source_tmp/manifest.json")"
[[ "$manifest_size" =~ ^[1-9][0-9]{0,3}$ && "$manifest_size" -le 4096 ]]
[[ "$(/usr/bin/stat -Lc '%u %g %h %a %s' "$source_tmp/manifest.json")" == "0 0 1 600 $manifest_size" ]]
/usr/bin/sync -f "$source_tmp"/*
/usr/bin/chmod 400 "$source_tmp"/*
while IFS=$'\t' read -r destination relative digest expected_size expected_dev expected_ino expected_uid expected_gid expected_mode; do
  [[ "$(/usr/bin/stat -Lc '%u %g %h %a %s' "$source_tmp/$destination")" == "0 0 1 400 $expected_size" ]]
  [[ "$(/usr/bin/sha256sum -- "$source_tmp/$destination" | { read -r value _; printf '%s' "$value"; })" == "$digest" ]]
done < "$native/files.tsv"
[[ "$(/usr/bin/stat -Lc '%u %g %h %a %s' "$source_tmp/manifest.json")" == "0 0 1 400 $manifest_size" ]]
/usr/bin/chmod 500 "$source_tmp"
/usr/bin/sync -f "$source_tmp"
[[ "$(/usr/bin/stat -Lc '%d:%i %u %a' "$source_tmp")" == "$source_dir_dev:$source_dir_ino 0 500" ]]
source_ready_tmp="$native/source.ready.tmp"
[[ ! -e "$source_ready_tmp" && ! -L "$source_ready_tmp" ]]
printf '%s %s %s\n' "$source_dir_dev" "$source_dir_ino" "$native_nonce" > "$source_ready_tmp"
/usr/bin/sync -f "$source_ready_tmp"
/usr/bin/mv -T --no-clobber -- "$source_ready_tmp" "$native/source.ready"
/usr/bin/sync -f "$native"
[[ "$(/usr/bin/stat -Lc '%d:%i' /run)" == "$source_parent_devino" && "$(/usr/bin/stat -Lc '%d' "$source_tmp")" == "$source_dir_dev" && ! -e "$source_root" && ! -L "$source_root" ]]
exec {source_fd}<"$source_tmp"
source_hold_devino="$(/usr/bin/stat -Lc '%d:%i' "/proc/self/fd/$source_fd")"
[[ "$source_hold_devino" == "$source_dir_dev:$source_dir_ino" ]]
/usr/bin/mv -T --no-clobber -- "$source_tmp" "$source_root"
[[ ! -e "$source_tmp" && ! -L "$source_tmp" ]]
[[ "$(/usr/bin/stat -Lc '%d:%i %u %a' "$source_root")" == "$source_hold_devino 0 500" ]]
[[ "$(/usr/bin/stat -Lc '%d:%i' "/proc/self/fd/$source_fd")" == "$source_hold_devino" ]]
source_dev="\${source_hold_devino%:*}"
source_ino="\${source_hold_devino#*:}"
while IFS=$'\t' read -r destination relative digest expected_size expected_dev expected_ino expected_uid expected_gid expected_mode; do
  [[ -f "$source_root/$destination" && ! -L "$source_root/$destination" ]]
  [[ "$(/usr/bin/stat -Lc '%u %g %h %a %s' "$source_root/$destination")" == "0 0 1 400 $expected_size" ]]
  [[ "$(/usr/bin/sha256sum -- "$source_root/$destination" | { read -r value _; printf '%s' "$value"; })" == "$digest" ]]
done < "$native/files.tsv"
[[ "$(/usr/bin/stat -Lc '%u %g %h %a %s' "$source_root/manifest.json")" == "0 0 1 400 $manifest_size" ]]
source_manifest_hash="$(/usr/bin/sha256sum -- "$source_root/manifest.json" | { read -r value _; printf '%s' "$value"; })"
native_manifest_hash="$(/usr/bin/sha256sum -- "$native/manifest.json" | { read -r value _; printf '%s' "$value"; })"
[[ "$source_manifest_hash" == "$native_manifest_hash" ]]
find_stage_mount
[[ "$(/usr/bin/stat -Lc '%d:%i' "$stage")" == "$stage_devino" ]]
read -r recorded_mount_id recorded_mount_device recorded_dev recorded_ino recorded_nonce < "$native/stage.identity"
[[ "$recorded_mount_id" == "$mount_id" && "$recorded_mount_device" == "$mount_device"
    && "$recorded_dev:$recorded_ino" == "$stage_devino" && "$recorded_nonce" == "$native_nonce" ]]
/usr/bin/umount -- "$stage"
while IFS= read -r line; do
  before="\${line%% - *}"
  read -r -a left_fields <<< "$before"
  [[ "\${left_fields[4]-}" != "$stage" ]] || exit 1
done < /proc/self/mountinfo
[[ "$(/usr/bin/stat -Lc '%d:%i %u %a' "$stage")" == "$stage_dev:$stage_ino 0 700" ]]
/usr/bin/rmdir -- "$stage"
/usr/bin/systemctl stop "$recovery_unit"
[[ "$(/usr/bin/systemctl show --property=ActiveState --value "$recovery_unit")" == inactive ]]
read -r recorded_recovery_dev recorded_recovery_ino < "$native/recovery.identity"
[[ "$(/usr/bin/stat -Lc '%d:%i %u %g %h %a' "$recovery_file")" == "$recorded_recovery_dev:$recorded_recovery_ino 0 0 1 644" ]]
/usr/bin/rm -- "$recovery_file" "$native/recover.sh" "$native/native.identity" "$native/files.tsv" "$native/manifest.json" "$native/stage.intent" "$native/stage.dir" "$native/stage.identity" "$native/source.intent" "$native/source.dir" "$native/source.ready" "$native/recovery.identity"
/usr/bin/systemctl daemon-reload
/usr/bin/rmdir -- "$native"
exec {source_fd}<&-
unset DOTUNNEL_SOURCE_DEV DOTUNNEL_SOURCE_INO
export DOTUNNEL_SOURCE_DEV="$source_dev"
export DOTUNNEL_SOURCE_INO="$source_ino"
exec /usr/bin/python3 -I -S "$source_root/runner_prepare.py" receipt-start "$run" "$attempt" <&\${payload_fd}
`;


async function pidBirth(pid) {
  let raw;
  try { raw = await fs.readFile(`/proc/${pid}/stat`, 'utf8'); } catch { fail('dispatcher-identity-unavailable'); }
  const suffix = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u);
  if (suffix.length < 20 || !/^[1-9][0-9]{0,19}$/u.test(suffix[19])) fail('dispatcher-identity-unavailable');
  return suffix[19];
}

async function verifyRunnerSourceIdentity(snapshot, pid, birth) {
  if (!Number.isSafeInteger(pid) || pid <= 0 || typeof birth !== 'string') fail('dispatcher-identity-unavailable');
  const proc = await fs.stat(`/proc/${pid}`, { bigint: true }).catch(() => null);
  if (!proc || proc.uid !== BigInt(snapshot.uid) || await pidBirth(pid) !== birth) fail('dispatcher-identity-changed');
  const cwd = await fs.stat(`/proc/${pid}/cwd`, { bigint: true }).catch(() => null);
  if (!cwd || cwd.dev.toString() !== snapshot.rootDev || cwd.ino.toString() !== snapshot.rootIno) fail('dispatcher-cwd-changed');
}

function base64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function bootstrapArgs(invocation, snapshot, manifestBytes, nonce, pid, birth) {
  const encodedFiles = base64(Buffer.from(filesTsv(snapshot), 'ascii'));
  return [
    '--quiet', '--wait', '--collect', '--pipe',
    '--expand-environment=no',
    `--unit=${invocation.names.bootstrapUnit}`,
    `--property=WorkingDirectory=/proc/${pid}/cwd`,
    '--property=MemoryMax=805306368',
    '--property=MemorySwapMax=0',
    '--property=CPUQuota=100%',
    '--property=TasksMax=128',
    '--property=RuntimeMaxSec=90s',
    '--property=KillMode=control-group',
    '--property=TimeoutStopSec=2s',
    '--property=OOMPolicy=kill',
    '--property=StandardOutput=null',
    '--property=StandardError=null',
    '--property=LogRateLimitIntervalSec=1s',
    '--property=PrivateMounts=no',
    '--property=Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin',
    '--property=Environment=LANG=C.UTF-8',
    '--property=Environment=LC_ALL=C.UTF-8',
    '--property=Environment=HOME=/root',
    '--property=UnsetEnvironment=BASH_ENV ENV GH_TOKEN GH_ENTERPRISE_TOKEN GITHUB_TOKEN GITHUB_OUTPUT GITHUB_WORKSPACE GITHUB_SHA GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_REPOSITORY GITHUB_REF GITHUB_EVENT_NAME GITHUB_ACTOR GITHUB_TRIGGERING_ACTOR GITHUB_JOB GITHUB_API_URL GITHUB_SERVER_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL ACTIONS_RESULTS_URL ACTIONS_CACHE_URL DOTUNNEL_BOOTSTRAP_MANIFEST DOTUNNEL_SOURCE_DEV DOTUNNEL_SOURCE_INO DOTUNNEL_RECEIPT_SCENARIO HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY NODE_OPTIONS NODE_PATH',
    `--property=Environment=DOTUNNEL_BOOTSTRAP_NONCE=${nonce}`,
    `--property=OnFailure=${invocation.names.bootstrapRecoveryUnit}`,
    '/usr/bin/bash', '-c', BOOTSTRAP_SCRIPT, '--',
    invocation.names.run,
    invocation.names.attempt,
    String(pid),
    birth,
    String(snapshot.uid),
    String(snapshot.gid),
    snapshot.rootDev,
    snapshot.rootIno,
    snapshot.rootMode,
    base64(manifestBytes),
    encodedFiles,
    nonce,
  ];
}

function runChild(executable, args, { deadlineNs, stdinBytes = null, timeoutMs = null } = {}) {
  const env = exactRootChildEnv();
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(executable, args, {
        cwd: '/',
        env,
        stdio: [stdinBytes === null ? 'ignore' : 'pipe', 'ignore', 'ignore'],
        windowsHide: true,
      });
    } catch {
      reject(new DispatchError('fixed-command-spawn-failed'));
      return;
    }
    let settled = false;
    const remaining = deadlineNs === undefined ? null : deadlineNs - process.hrtime.bigint();
    const boundedMs = timeoutMs ?? (remaining === null ? 90_000 : Math.max(1, Math.min(90_000, Number(remaining / 1_000_000n))));
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new DispatchError('fixed-command-timeout'));
    }, boundedMs);
    child.once('error', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new DispatchError('fixed-command-spawn-failed'));
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code === 0 && signal === null) resolve();
      else reject(new DispatchError('fixed-command-failed'));
    });
    if (stdinBytes !== null) {
      const clearStdin = () => stdinBytes.fill(0);
      child.stdin.once('error', clearStdin);
      child.stdin.end(stdinBytes, clearStdin);
    }
  });
}

async function preflightUnitAndPaths(invocation) {
  for (const pathname of rootFilesystemPaths(invocation.names)) await assertAbsent(pathname);
  const unitFile = `/run/systemd/system/${invocation.names.bootstrapRecoveryUnit}`;
  await assertAbsent(unitFile);
  const bootstrapState = await queryUnitState(invocation.names.bootstrapUnit);
  const recoveryState = await queryUnitState(invocation.names.bootstrapRecoveryUnit);
  if (bootstrapState !== 'not-found' || recoveryState !== 'not-found') fail('runner-unit-collision');
}

async function queryUnitState(unit) {
  const output = await runBoundedReadOnlySystemctl(unit);
  return output;
}

function runBoundedReadOnlySystemctl(unit) {
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/sudo', ['-n', '--', '/usr/bin/systemctl', 'show', '--property=LoadState', '--value', unit], {
      cwd: '/', env: exactRootChildEnv(), stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true,
    });
    let bytes = 0;
    let output = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new DispatchError('system-manager-query-timeout'));
    }, 2000);
    child.stdout.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > 128 || settled) {
        child.kill('SIGKILL');
        return;
      }
      output += chunk.toString('ascii');
    });
    child.once('error', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new DispatchError('system-manager-query-failed'));
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0 || signal !== null || bytes > 128 || !/^(?:not-found|loaded)\n?$/u.test(output)) {
        reject(new DispatchError('system-manager-query-failed'));
      } else {
        resolve(output.trim());
      }
    });
  });
}

async function promoteSources(invocation, snapshot, sourceWorkspace, sourceManifestBytes, manifestCommit, startedAtMs, scenario, runtime, pid, birth, cancellation) {
  if (cancellation.firstNoticeNs !== null) fail('dispatch-cancelled-before-bootstrap');
  await verifySourceSnapshot(sourceWorkspace, snapshot);
  await verifyCheckoutHead(sourceWorkspace, manifestCommit, snapshot.uid, snapshot.gid);
  await verifyRunnerSourceIdentity(snapshot, pid, birth);
  if (cancellation.firstNoticeNs !== null) fail('dispatch-cancelled-before-bootstrap');
  const beforePreflight = remainingJobNanoseconds(startedAtMs, Date.now());
  if (beforePreflight < MIN_JOB_WINDOW_NS || beforePreflight > JOB_LIMIT_NS) fail('insufficient-job-window');
  await preflightUnitAndPaths(invocation);
  if (cancellation.firstNoticeNs !== null) fail('dispatch-cancelled-before-bootstrap');
  const nonce = randomBytes(16).toString('hex');
  const args = bootstrapArgs(invocation, snapshot, sourceManifestBytes, nonce, pid, birth);
  const gateMonotonicNs = process.hrtime.bigint();
  const remaining = remainingJobNanoseconds(startedAtMs, Date.now());
  if (remaining < MIN_JOB_WINDOW_NS || remaining > JOB_LIMIT_NS) fail('insufficient-job-window');
  const outerDeadlineNs = gateMonotonicNs + remaining;
  cancellation.setOuterDeadlineNs(outerDeadlineNs);
  const payload = payloadBytes(invocation, scenario, outerDeadlineNs, runtime);
  runtime.ACTIONS_RUNTIME_TOKEN = '';
  runtime.ACTIONS_RUNTIME_URL = '';
  runtime.ACTIONS_RESULTS_URL = '';
  runtime = null;
  clearCredentialEnvironment();
  try {
    const launchRemaining = remainingJobNanoseconds(startedAtMs, Date.now());
    if (cancellation.firstNoticeNs !== null || launchRemaining < MIN_JOB_WINDOW_NS || launchRemaining > JOB_LIMIT_NS
        || outerDeadlineNs - process.hrtime.bigint() < MIN_JOB_WINDOW_NS) fail('insufficient-job-window');
    await runChild('/usr/bin/sudo', ['-n', '--', '/usr/bin/systemd-run', ...args], {
      deadlineNs: outerDeadlineNs,
      stdinBytes: payload,
      timeoutMs: Math.min(95_000, Math.max(1, Number((outerDeadlineNs - process.hrtime.bigint()) / 1_000_000n))),
    });
  } finally {
    payload.fill(0);
  }
  return outerDeadlineNs;
}


function validateStatus(value, names) {
  const fields = [
    'schema', 'run', 'attempt', 'state', 'ready', 'running', 'cancel_ack',
    'cancel_notice_ns', 'cancel_received_ns', 'live_at_notice', 'terminal',
    'readiness_publication', 'terminal_publication', 'publisher_exit',
    'snapshot_sha256', 'updated_ns', 'boot_id', 'nonce', 'source',
  ];
  if (!exactKeys(value, fields) || value.schema !== 1 || value.run !== names.run || value.attempt !== names.attempt
      || !['WAITING', 'READY', 'CANCEL_REQUESTED', 'CLEANUP', 'TERMINAL'].includes(value.state)
      || typeof value.ready !== 'boolean' || typeof value.running !== 'boolean' || typeof value.cancel_ack !== 'boolean'
      || typeof value.terminal !== 'boolean'
      || !(value.cancel_notice_ns === null || positiveId(value.cancel_notice_ns))
      || !(value.cancel_received_ns === null || positiveId(value.cancel_received_ns))
      || !(value.live_at_notice === null || typeof value.live_at_notice === 'boolean')
      || !['PENDING', 'LOCAL_PUBLISHED', 'FAILED', 'UNKNOWN'].includes(value.readiness_publication)
      || !['PENDING', 'LOCAL_PUBLISHED', 'FAILED', 'UNKNOWN'].includes(value.terminal_publication)
      || !(value.publisher_exit === null || (Number.isInteger(value.publisher_exit) && value.publisher_exit >= 0 && value.publisher_exit <= 255))
      || !(value.snapshot_sha256 === null || (typeof value.snapshot_sha256 === 'string' && /^[0-9a-f]{64}$/u.test(value.snapshot_sha256)))
      || !positiveId(value.updated_ns)
      || typeof value.boot_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value.boot_id)
      || typeof value.nonce !== 'string' || !/^[0-9a-f]{32}$/u.test(value.nonce)
      || !exactKeys(value.source, ['commit', 'closure_sha256'])
      || typeof value.source.commit !== 'string' || !/^[0-9a-f]{40}$/u.test(value.source.commit)
      || typeof value.source.closure_sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(value.source.closure_sha256)) fail('invalid-root-status');
  if (value.cancel_ack !== (value.cancel_notice_ns !== null)
      || (value.cancel_notice_ns === null) !== (value.cancel_received_ns === null)
      || (value.cancel_ack && BigInt(value.cancel_notice_ns) > BigInt(value.cancel_received_ns))) fail('invalid-root-cancel-receipt');
  if (value.terminal && value.state !== 'TERMINAL') fail('invalid-root-terminal-state');
  return value;
}

function bindStatus(value, names, binding) {
  const status = validateStatus(value, names);
  if (binding.bootId === null || binding.source === null
      || status.boot_id !== binding.bootId
      || status.source.commit !== binding.source.commit
      || status.source.closure_sha256 !== binding.source.closure_sha256
      || (binding.nonce !== null && status.nonce !== binding.nonce)) fail('root-status-binding-mismatch');
  binding.nonce = status.nonce;
  return status;
}

function bindCancelAck(value, names, binding, expectedNoticeNs) {
  const fields = [
    'schema', 'tag', 'run', 'attempt', 'cancel_ack', 'cancel_notice_ns',
    'cancel_received_ns', 'boot_id', 'nonce', 'source',
  ];
  if (!exactKeys(value, fields) || value.schema !== 1 || value.tag !== 'CANCEL_ACK'
      || value.run !== names.run || value.attempt !== names.attempt
      || value.cancel_ack !== true || !positiveId(value.cancel_notice_ns)
      || value.cancel_notice_ns !== expectedNoticeNs || !positiveId(value.cancel_received_ns)
      || BigInt(value.cancel_notice_ns) > BigInt(value.cancel_received_ns)
      || BigInt(value.cancel_received_ns) > BigInt(value.cancel_notice_ns) + CANCEL_DELIVERY_NS
      || typeof value.boot_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value.boot_id)
      || typeof value.nonce !== 'string' || !/^[0-9a-f]{32}$/u.test(value.nonce)
      || !exactKeys(value.source, ['commit', 'closure_sha256'])
      || typeof value.source.commit !== 'string' || !/^[0-9a-f]{40}$/u.test(value.source.commit)
      || typeof value.source.closure_sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(value.source.closure_sha256)) fail('invalid-root-cancel-ack');
  if ((binding.bootId !== null && binding.bootId !== value.boot_id)
      || (binding.nonce !== null && binding.nonce !== value.nonce)
      || (binding.source !== null && canonicalJson(binding.source) !== canonicalJson(value.source))) fail('root-control-binding-mismatch');
  if (binding.bootId === null) binding.bootId = value.boot_id;
  if (binding.nonce === null) binding.nonce = value.nonce;
  if (binding.source === null) binding.source = Object.freeze({ ...value.source });
  return value;
}

function validateControlRequest(request) {
  if (exactKeys(request, ['op']) && request.op === 'STATUS') return;
  if (exactKeys(request, ['op', 'notice_ns']) && request.op === 'CANCEL'
      && typeof request.notice_ns === 'string' && /^[1-9][0-9]{0,19}$/u.test(request.notice_ns)) return;
  fail('invalid-control-request');
}

export function requestControlStream(socketPath, request, deadlineNs) {
  validateControlRequest(request);
  if (typeof socketPath !== 'string' || typeof deadlineNs !== 'bigint') return Promise.reject(new DispatchError('invalid-control-endpoint'));
  const requestBytes = Buffer.from(`${JSON.stringify(request)}\n`, 'ascii');
  if (requestBytes.length > MAX_CONTROL_REQUEST_BYTES) return Promise.reject(new DispatchError('status-request-too-large'));
  const initialRemaining = deadlineNs - process.hrtime.bigint();
  if (initialRemaining <= 0n) return Promise.reject(new DispatchError('status-deadline-expired'));
  const timeoutMs = Math.max(1, Math.min(1000, Number(initialRemaining / 1_000_000n)));
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    let settled = false;
    let bytes = Buffer.alloc(0);
    const timer = setTimeout(() => finish(new DispatchError('status-stream-timeout')), timeoutMs);
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    socket.setTimeout(timeoutMs, () => finish(new DispatchError('status-stream-timeout')));
    socket.once('connect', () => {
      if (process.hrtime.bigint() >= deadlineNs) {
        finish(new DispatchError('status-deadline-expired'));
        return;
      }
      socket.write(requestBytes, (error) => {
        if (error) finish(new DispatchError('status-stream-write-failed'));
      });
    });
    socket.on('data', (chunk) => {
      if (settled) return;
      if (bytes.length + chunk.length > MAX_CONTROL_RESPONSE_BYTES) {
        finish(new DispatchError('status-frame-too-large'));
        return;
      }
      bytes = Buffer.concat([bytes, chunk], bytes.length + chunk.length);
      const newline = bytes.indexOf(0x0a);
      if (newline === -1) return;
      if (newline !== bytes.length - 1) {
        finish(new DispatchError('status-frame-invalid'));
        return;
      }
      try {
        const value = parseStrictJson(bytes.subarray(0, newline), MAX_CONTROL_RESPONSE_BYTES - 1);
        if (!isRecord(value)) fail('invalid-root-status');
        finish(null, value);
      } catch (error) {
        finish(error instanceof DispatchError ? error : new DispatchError('status-frame-invalid'));
      }
    });
    socket.once('error', () => finish(new DispatchError('status-stream-unavailable')));
    socket.once('end', () => {
      if (!settled) finish(new DispatchError('status-frame-incomplete'));
    });
  });
}

async function assertRootControlSocket(socketPath, names) {
  const directory = path.dirname(socketPath);
  if (directory !== names.control || path.basename(socketPath) !== 'status.sock') fail('invalid-control-path');
  let dirStat;
  let socketStat;
  try {
    dirStat = await fs.lstat(directory, { bigint: true });
    socketStat = await fs.lstat(socketPath, { bigint: true });
  } catch { fail('root-control-unavailable'); }
  if (!dirStat.isDirectory() || dirStat.uid !== 0n || Number(dirStat.mode & 0o777n) !== 0o711
      || (dirStat.mode & 0o022n) !== 0n || socketStat.isSymbolicLink() || !socketStat.isSocket()
      || socketStat.uid !== 0n || socketStat.gid !== BigInt(process.getgid()) || Number(socketStat.mode & 0o777n) !== 0o660
      || socketStat.nlink !== 1n) fail('root-control-identity-refused');
  const runStat = await fs.lstat(ROOT_PATH, { bigint: true }).catch(() => null);
  if (!runStat || !runStat.isDirectory() || runStat.uid !== 0n || (runStat.mode & 0o022n) !== 0n) fail('root-control-ancestry-refused');
  return Object.freeze({ dev: socketStat.dev.toString(), ino: socketStat.ino.toString(), gid: socketStat.gid.toString() });
}

async function requestRootControl(socketPath, request, deadlineNs, names, binding) {
  const identity = await assertRootControlSocket(socketPath, names);
  const response = await requestControlStream(socketPath, request, deadlineNs);
  const current = await assertRootControlSocket(socketPath, names);
  if (current.dev !== identity.dev || current.ino !== identity.ino || current.gid !== identity.gid) fail('root-control-identity-changed');
  if (exactKeys(response, ['error']) && response.error === 'control peer refused') fail('root-control-peer-refused');
  if (request.op === 'CANCEL') {
    const ack = bindCancelAck(response, names, binding, request.notice_ns);
    if (BigInt(ack.cancel_received_ns) > deadlineNs) fail('invalid-root-cancel-ack');
    return ack;
  }
  return bindStatus(response, names, binding);
}

export async function openSearchDirectory(directoryPath) {
  // Linux O_PATH is not exported by Node's fs.constants. It pins the
  // search-only root directory without requiring directory-read permission.
  const linuxOPath = 0x200000;
  return fs.open(directoryPath, linuxOPath | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
}

function directoryIdentity(stat) {
  return [stat.dev, stat.ino, stat.uid, stat.gid, stat.mode].join(':');
}

async function readTerminalStatus(invocation, binding) {
  let rootFd;
  let directoryFd;
  let recordFd;
  try {
    rootFd = await fs.open(ROOT_PATH, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC);
    const rootStat = await rootFd.stat({ bigint: true });
    if (!rootStat.isDirectory() || rootStat.uid !== 0n || (rootStat.mode & 0o022n) !== 0n) fail('root-control-ancestry-refused');
    const directoryPath = `/proc/self/fd/${rootFd.fd}/${path.basename(invocation.names.control)}`;
    directoryFd = await openSearchDirectory(directoryPath);
    const directoryStat = await directoryFd.stat({ bigint: true });
    if (!directoryStat.isDirectory() || directoryStat.uid !== 0n
        || Number(directoryStat.mode & 0o777n) !== 0o711
        || directoryIdentity(directoryStat) !== directoryIdentity(await fs.lstat(directoryPath, { bigint: true }))) fail('root-control-identity-refused');
    const recordPath = `/proc/self/fd/${directoryFd.fd}/terminal-status.json`;
    recordFd = await fs.open(recordPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK | fsConstants.O_CLOEXEC);
    const before = await recordFd.stat({ bigint: true });
    if (!before.isFile() || before.uid !== 0n || before.nlink !== 1n
        || Number(before.mode & 0o777n) !== 0o444
        || before.size <= 0n || before.size > BigInt(MAX_CONTROL_RESPONSE_BYTES)) fail('terminal-record-identity-refused');
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let used = 0;
    while (used < bytes.length) {
      const result = await recordFd.read(bytes, used, bytes.length - used, null);
      if (result.bytesRead === 0) break;
      used += result.bytesRead;
    }
    if (used !== Number(before.size)
        || fileIdentity(before) !== fileIdentity(await recordFd.stat({ bigint: true }))
        || fileIdentity(before) !== fileIdentity(await fs.lstat(recordPath, { bigint: true }))
        || directoryIdentity(directoryStat) !== directoryIdentity(await directoryFd.stat({ bigint: true }))
        || directoryIdentity(directoryStat) !== directoryIdentity(await fs.lstat(directoryPath, { bigint: true }))
        || directoryIdentity(rootStat) !== directoryIdentity(await fs.lstat(ROOT_PATH, { bigint: true }))) fail('terminal-record-identity-changed');
    const wrapper = parseStrictJson(bytes.subarray(0, used), MAX_CONTROL_RESPONSE_BYTES);
    if (!exactKeys(wrapper, ['schema', 'context', 'source', 'boot_id', 'nonce', 'status'])
        || wrapper.schema !== 1
        || canonicalJson(wrapper.context) !== canonicalJson(invocation.context)
        || canonicalJson(wrapper.source) !== canonicalJson(binding.source)
        || wrapper.boot_id !== binding.bootId
        || !isRecord(wrapper.status) || wrapper.status.nonce !== wrapper.nonce
        || wrapper.status.boot_id !== wrapper.boot_id
        || canonicalJson(wrapper.status.source) !== canonicalJson(wrapper.source)) fail('terminal-record-binding-mismatch');
    const status = bindStatus(wrapper.status, invocation.names, binding);
    if (!status.terminal) fail('terminal-record-not-terminal');
    return status;
  } catch (error) {
    if (error instanceof DispatchError) throw error;
    if (error?.code === 'ENOENT') fail('terminal-record-unavailable');
    fail('terminal-record-read-refused');
  } finally {
    if (recordFd) await recordFd.close().catch(() => {});
    if (directoryFd) await directoryFd.close().catch(() => {});
    if (rootFd) await rootFd.close().catch(() => {});
  }
}


function transientControlFailure(error) {
  return error instanceof DispatchError
    && ['root-control-unavailable', 'status-stream-unavailable', 'status-stream-timeout', 'status-frame-incomplete'].includes(error.code);
}

export function installCancellationHandler(socketPath, outerDeadlineNs, request = requestControlStream) {
  let firstNoticeNs = null;
  let cancelPromise = null;
  let outerDeadline = outerDeadlineNs;
  const onSignal = () => {
    if (firstNoticeNs !== null) return;
    firstNoticeNs = process.hrtime.bigint().toString();
    const noticeDeadline = BigInt(firstNoticeNs) + CANCEL_DELIVERY_NS;
    const deadline = typeof outerDeadline === 'bigint' && outerDeadline < noticeDeadline ? outerDeadline : noticeDeadline;
    cancelPromise = (async () => {
      while (process.hrtime.bigint() < deadline) {
        let status;
        try {
          status = await request(socketPath, { op: 'CANCEL', notice_ns: firstNoticeNs }, deadline);
        } catch (error) {
          if (!transientControlFailure(error)) return false;
        }
        if (status?.cancel_ack === true) {
          return process.hrtime.bigint() <= deadline
            && status.tag === 'CANCEL_ACK'
            && status.cancel_notice_ns === firstNoticeNs
            && positiveId(status.cancel_received_ns)
            && BigInt(status.cancel_received_ns) <= deadline
            && BigInt(firstNoticeNs) <= BigInt(status.cancel_received_ns);
        }
        const remaining = deadline - process.hrtime.bigint();
        if (remaining <= 0n) break;
        await new Promise((resolve) => setTimeout(resolve, Math.max(1, Math.min(25, Number(remaining / 1_000_000n)))));
      }
      return false;
    })();
  };
  process.on('SIGINT', onSignal);
  return Object.freeze({
    get firstNoticeNs() { return firstNoticeNs; },
    get cancelPromise() { return cancelPromise; },
    setOuterDeadlineNs(value) { if (typeof value === 'bigint') outerDeadline = value; },
    close() { process.off('SIGINT', onSignal); },
  });
}

async function waitUntilNextPoll(deadlineNs) {
  const remaining = deadlineNs - process.hrtime.bigint();
  if (remaining <= 0n) fail('outer-deadline-expired');
  await new Promise((resolve) => setTimeout(resolve, Math.max(1, Math.min(CONTROL_POLL_MS, Number(remaining / 1_000_000n)))));
}

export function terminalStatusReady(status, noticeNs, readinessObserved) {
  if (status.readiness_publication === 'FAILED' || status.readiness_publication === 'UNKNOWN') fail('readiness-publication-failed');
  if (status.terminal_publication === 'FAILED' || status.terminal_publication === 'UNKNOWN') fail('terminal-publication-failed');
  if (noticeNs !== null && status.cancel_ack && status.cancel_notice_ns !== noticeNs) fail('root-cancel-notice-mismatch');
  if (!status.terminal || status.terminal_publication !== 'LOCAL_PUBLISHED' || status.publisher_exit === null) return false;
  if (status.publisher_exit !== 0) fail('terminal-publisher-failed');
  if (noticeNs !== null && (!status.cancel_ack || status.cancel_notice_ns !== noticeNs)) fail('root-cancel-not-acknowledged');
  if (!readinessObserved && status.readiness_publication !== 'LOCAL_PUBLISHED') fail('readiness-publication-missing');
  return true;
}

async function pollTerminal(invocation, outerDeadlineNs, cancellation, binding) {
  const socketPath = `${invocation.names.control}/status.sock`;
  let readinessObserved = false;
  while (process.hrtime.bigint() < outerDeadlineNs) {
    const perRequestDeadline = process.hrtime.bigint() + 1_000_000_000n;
    let status;
    try {
      status = await requestRootControl(socketPath, { op: 'STATUS' },
        perRequestDeadline < outerDeadlineNs ? perRequestDeadline : outerDeadlineNs, invocation.names, binding);
    } catch (error) {
      if (!transientControlFailure(error)) throw error;
      try {
        status = await readTerminalStatus(invocation, binding);
      } catch (recordError) {
        if (!(recordError instanceof DispatchError) || recordError.code !== 'terminal-record-unavailable') throw recordError;
        await waitUntilNextPoll(outerDeadlineNs);
        continue;
      }
    }
    if (status.ready && status.readiness_publication === 'LOCAL_PUBLISHED') readinessObserved = true;
    if (terminalStatusReady(status, cancellation.firstNoticeNs, readinessObserved)) {
      if (cancellation.firstNoticeNs !== null) await cancellation.cancelPromise;
      return status;
    }
    await waitUntilNextPoll(outerDeadlineNs);
  }
  fail('outer-deadline-expired');
}

function payloadBytes(invocation, scenario, outerDeadlineNs, runtime) {
  const payload = {
    context: invocation.context,
    dispatcher_pid: process.pid,
    scenario,
    outer_deadline_ns: outerDeadlineNs.toString(),
    runtime,
  };
  const bytes = Buffer.from(canonicalJson(payload), 'ascii');
  if (bytes.length > MAX_RUNTIME_PAYLOAD_BYTES) fail('runtime-payload-too-large');
  return bytes;
}

function clearCredentialEnvironment() {
  for (const name of [
    'GITHUB_TOKEN',
    'GH_TOKEN',
    'GH_ENTERPRISE_TOKEN',
    'ACTIONS_RUNTIME_TOKEN',
    'ACTIONS_RUNTIME_URL',
    'ACTIONS_RESULTS_URL',
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
    'ACTIONS_ID_TOKEN_REQUEST_URL',
    'DOTUNNEL_BOOTSTRAP_MANIFEST',
    'DOTUNNEL_SOURCE_DEV',
    'DOTUNNEL_SOURCE_INO',
  ]) {
    if (Object.hasOwn(process.env, name)) process.env[name] = '';
  }
}

async function dispatch() {
  const invocation = readInvocation(process.env);
  const binding = { bootId: null, source: null, nonce: null };
  const cancellation = installCancellationHandler(`${invocation.names.control}/status.sock`, process.hrtime.bigint() + JOB_LIMIT_NS,
    (socketPath, request, deadlineNs) => requestRootControl(socketPath, request, deadlineNs, invocation.names, binding));
  let sourceSnapshot;
  let sourceWorkspace;
  let runtime = null;
  try {
    await verifyNodeRuntime();
    if (cancellation.firstNoticeNs !== null) fail('dispatch-cancelled-before-bootstrap');
    const scenario = process.env.DOTUNNEL_RECEIPT_SCENARIO;
    if (scenario !== 'normal' && scenario !== 'workflow-cancel') fail('invalid-receipt-scenario');
    const manifest = parseBootstrapManifest(process.env.DOTUNNEL_BOOTSTRAP_MANIFEST);
    runtime = runtimeCredentials(process.env);
    verifyRuntimeCredentials(runtime);
    sourceWorkspace = await fixedSourceCheckout(process.env.GITHUB_WORKSPACE);
    await verifyCheckoutHead(sourceWorkspace, manifest.commit);
    sourceSnapshot = await inspectSources(sourceWorkspace, manifest);
    const metadata = await verifyGitHubMetadata(invocation, manifest, process.env);
    const runnerBirth = await pidBirth(process.pid);
    await verifyRunnerSourceIdentity(sourceSnapshot, process.pid, runnerBirth);
    await checkNativeBinaries();
    const { sourceManifestBytes, closureSha256 } = checkedClosure(manifest);
    binding.source = Object.freeze({ commit: manifest.commit, closure_sha256: closureSha256 });
    binding.bootId = (await fs.readFile('/proc/sys/kernel/random/boot_id', 'ascii')).trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(binding.bootId)) fail('boot-identity-unavailable');
    const start = promoteSources(invocation, sourceSnapshot, sourceWorkspace, sourceManifestBytes,
      manifest.commit, metadata.startedAtMs, scenario, runtime, process.pid, runnerBirth, cancellation);
    runtime = null;
    const outerDeadlineNs = await start;
    await sourceSnapshot.close();
    sourceSnapshot = null;
    await pollTerminal(invocation, outerDeadlineNs, cancellation, binding);
  } finally {
    if (sourceSnapshot) await sourceSnapshot.close();
    clearCredentialEnvironment();
    runtime = null;
    cancellation.close();
  }
}


export { rootChildEnvironment };

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  dispatch().catch((error) => {
    const code = error instanceof DispatchError ? error.code : 'dispatcher-failed';
    process.stderr.write(`runner-dispatch:${code}\n`);
    process.exitCode = 1;
  });
}
