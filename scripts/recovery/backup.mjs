#!/usr/bin/env node
import { mkdtemp, writeFile, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { authorizeDrive } from "./drive.mjs";
import { PgSnapshot, productionPgEnv } from "./postgres.mjs";
import { delay, download, encrypt, fileDigest, jsonResponse, run, sha256, verifiedUpload, verifyStoredCipher } from "./io.mjs";
import { retain } from "./retention.mjs";
const OBJECT_MAX = 512 * 1024 * 1024;
export function configuration(raw = process.env) {
  if (raw.RECOVERY_BACKUP_ENABLED !== "true" || !raw.GITHUB_ACTIONS || raw.GITHUB_REF !== "refs/heads/main") throw new Error("backups require explicitly enabled trusted main workflow");
  const url = new URL(raw.RECOVERY_APP_ORIGIN ?? "");
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || typeof raw.RECOVERY_RUNNER_SECRET !== "string" || raw.RECOVERY_RUNNER_SECRET.length < 32) throw new Error("canonical recovery origin/credential required");
  const target = JSON.parse(raw.RECOVERY_DRIVE_TARGET_JSON ?? "null");
  if (!target || typeof target.ownerEmail !== "string" || !target.ownerEmail.includes("@") || !/^age1/.test(target.recipient ?? "")) throw new Error("owner/public recipient configuration required");
  if (!/^[a-z0-9]{20}$/.test(raw.RECOVERY_SOURCE_PROJECT_REF ?? "")) throw new Error("source project identity required");
  return { target, origin: url.origin, secret: raw.RECOVERY_RUNNER_SECRET, sourceProject: raw.RECOVERY_SOURCE_PROJECT_REF };
}
export class RecoveryGateway {
  constructor({ origin, secret, sourceProject, fetcher = fetch, signal }) { this.origin = origin; this.secret = secret; this.sourceProject = sourceProject; this.fetcher = fetcher; this.signal = signal; }
  async post(path, body, timeout = 20_000) {
    const signal = AbortSignal.timeout(timeout);
    return this.fetcher(`${this.origin}/api/internal/recovery${path}`, { method: "POST", redirect: "error", headers: { Authorization: `Bearer ${this.secret}`, "Content-Type": "application/json" }, body: JSON.stringify(body), signal: this.signal ? AbortSignal.any([this.signal, signal]) : signal });
  }
  async control(action, runId, receipt) { const result = await jsonResponse(await this.post("", { action, ...(runId ? { runId } : {}), ...(receipt ? { receipt } : {}) }), 64 * 1024); if (!this.sourceProject || result.sourceProject !== this.sourceProject) throw new Error("gateway/database project mismatch"); return result.run; }
  object(runId, bucket, path) { return this.post("/object", { runId, bucket, path }, 55_000); }
}
function assertLease(run, { allowDraining = false } = {}) {
  if (Number(run?.overdueDeletions ?? 0) > 0) throw new Error("unresolved storage deletion fence: operator reconciliation required; capture refused");
  if (!run?.id || run.state !== "capturing" || Date.parse(run.lease_until) <= Date.now() + 15_000 || (!allowDraining && run.draining !== false) || Date.parse(run.started_at) < Date.now() - 115 * 60_000) throw new Error("capture lease unavailable or deadline reached");
}
export function objectVersion(object) { return sha256(JSON.stringify([object.bucket, object.path, object.id, object.updatedAt, object.etag, object.size])); }
function props(kind, runId) { return { jodjamBackup: "1", kind, runId }; }
export async function capture({ config, drive, gateway, postgres, directory, signal, now = () => new Date() }) {
  let lease, sealed = false, timer, renewalFailure;
  const abort = new AbortController(); const activeSignal = signal ? AbortSignal.any([signal, abort.signal]) : abort.signal;
  const live = () => { activeSignal.throwIfAborted(); if (renewalFailure) throw renewalFailure; assertLease(lease); };
  try {
    await drive.preflight(config.target);
    const previous = await gateway.control("latest");
    // Repair a crash after successful server seal but before marking the opaque Drive index committed.
    if (previous?.receipt?.sealId) await drive.markCommitted(previous.receipt.sealId);
    const initialFiles = await drive.list(config.target.archiveFolderId);
    lease = await gateway.control("begin"); assertLease(lease, { allowDraining: true });
    let renewing = false;
    timer = setInterval(async () => {
      if (renewing) return; renewing = true;
      try { lease = await gateway.control("renew", lease.id); assertLease(lease, { allowDraining: true }); }
      catch { renewalFailure = new Error("capture renewal failed"); abort.abort(renewalFailure); }
      finally { renewing = false; }
    }, 60_000);
    while (lease.draining !== false) { await delay(500); lease = await gateway.control("status", lease.id); assertLease(lease, { allowDraining: true }); }
    live(); postgres.config.signal = activeSignal;
    await postgres.assertReadonlyRole();
    await postgres.begin(); const snapshot = postgres.snapshot; const objects = postgres.objects;
    await postgres.dump(directory); await postgres.close(); live();
    const existing = new Map();
    for (const file of initialFiles.filter(file => file.appProperties?.kind === "object")) {
      const p = file.appProperties;
      if (/^[a-f0-9]{64}$/.test(p.objectVersion ?? "") && /^[a-f0-9]{64}$/.test(p.plainSha256 ?? "") && /^[a-f0-9]{64}$/.test(p.cipherSha256 ?? "") && (!file.sha256Checksum || p.cipherSha256 === file.sha256Checksum) && Number(file.size) > 0) existing.set(p.objectVersion, file);
    }
    const newBytes = objects.filter(object => !existing.has(objectVersion(object))).reduce((sum, object) => sum + object.size + 65536, 0);
    const databaseSize = (await fileDigest(join(directory, "database.dump"))).size;
    await drive.preflight(config.target, newBytes + databaseSize * 1.1 + 10 * 1024 * 1024);
    const manifest = { version: 1, sourceProject: config.sourceProject, runId: lease.id, createdAt: now().toISOString(), snapshot, objects: [] };
    const refs = [];
    for (let i = 0; i < objects.length; i++) {
      live(); const object = objects[i], version = objectVersion(object); let reference; let plainSha;
      const old = existing.get(version);
      if (old) {
        // Google's binary checksum must match the previous verified cipher receipt, not merely a mutable filename.
        const actual = await drive.metadata(old.id);
        if (Number(actual.size) !== Number(old.size) || !actual.parents?.includes(config.target.archiveFolderId) || Number(old.appProperties.plainSize) !== object.size) throw new Error("reused cipher verification failed");
        await verifyStoredCipher(drive, actual, old.appProperties.cipherSha256, Number(old.size));
        reference = { id: old.id, cipherSha256: old.appProperties.cipherSha256, cipherSize: Number(actual.size) }; plainSha = old.appProperties.plainSha256;
      } else {
        const plain = join(directory, `object-${i}.plain`), cipher = join(directory, `object-${i}.age`);
        const digest = await download(await gateway.object(lease.id, object.bucket, object.path), plain, { expectedSize: object.size, maxBytes: OBJECT_MAX, signal: activeSignal });
        plainSha = digest.sha256; const encrypted = await encrypt(plain, cipher, config.target.recipient, { signal: activeSignal, age: config.age });
        await rm(plain); live();
        reference = await verifiedUpload(drive, cipher, { name: `object-${version}.age`, mimeType: "application/octet-stream", parents: [config.target.archiveFolderId], appProperties: { ...props("object", lease.id), objectVersion: version, plainSha256: plainSha, plainSize: String(object.size), cipherSha256: encrypted.sha256 } });
        await rm(cipher); existing.set(version, { id: reference.id, size: String(reference.cipherSize), sha256Checksum: reference.cipherSha256, appProperties: { objectVersion: version, plainSha256: plainSha, plainSize: String(object.size), cipherSha256: reference.cipherSha256 } });
      }
      refs.push(reference); manifest.objects.push({ ...object, storageId: object.id, plainSha256: plainSha, ...reference });
    }
    live();
    await writeFile(join(directory, "manifest.json"), JSON.stringify(manifest), { mode: 0o600, flag: "wx" });
    const manifestSha256 = (await fileDigest(join(directory, "manifest.json"))).sha256;
    await run("tar", ["-cf", join(directory, "snapshot.tar"), "-C", directory, "database.dump", "roles.sql", "manifest.json"], { signal: activeSignal });
    const encrypted = await encrypt(join(directory, "snapshot.tar"), join(directory, "snapshot.age"), config.target.recipient, { signal: activeSignal, age: config.age });
    live();
    const archive = await verifiedUpload(drive, join(directory, "snapshot.age"), { name: `snapshot-${lease.id}.age`, mimeType: "application/octet-stream", parents: [config.target.archiveFolderId], appProperties: { ...props("snapshot", lease.id), cipherSha256: encrypted.sha256 } });
    const seal = { version: 1, runId: lease.id, createdAt: manifest.createdAt, archive, manifestSha256, objects: refs };
    await writeFile(join(directory, "seal.json"), JSON.stringify(seal), { mode: 0o600, flag: "wx" });
    const sealFile = await verifiedUpload(drive, join(directory, "seal.json"), { name: `seal-${lease.id}.json`, mimeType: "application/json", parents: [config.target.archiveFolderId], appProperties: { ...props("seal", lease.id), committed: "0" } });
    live();
    const receipt = { archiveId: archive.id, cipherSha256: archive.cipherSha256, manifestSha256, snapshot, restoreVerified: false, sealId: sealFile.id, objectCount: refs.length, createdAt: manifest.createdAt };
    const done = await gateway.control("seal", lease.id, receipt);
    if (done?.state !== "sealed" || done.id !== lease.id) throw new Error("server seal failed");
    sealed = true; clearInterval(timer); timer = null;
    await drive.markCommitted(sealFile.id);
    const retention = await retain(drive, await drive.list(config.target.archiveFolderId), lease.id, config.target.archiveFolderId);
    return { runId: lease.id, objects: refs.length, retention, receipt };
  } finally {
    if (timer) clearInterval(timer);
    await postgres.close().catch(() => {});
    if (lease && !sealed) await gateway.control("fail", lease.id).catch(() => {});
  }
}
export async function main(raw = process.env) {
  const config = configuration(raw), directory = await mkdtemp(join(tmpdir(), "jodjam-recovery-")); await chmod(directory, 0o700);
  try {
    if (!raw.RECOVERY_DATABASE_CA_BASE64) throw new Error("verified TLS CA required");
    const ca = join(directory, "database-ca.pem"); await writeFile(ca, Buffer.from(raw.RECOVERY_DATABASE_CA_BASE64, "base64"), { mode: 0o600 });
    await encrypt("/dev/null", join(directory, "recipient-check.age"), config.target.recipient);
    const drive = await authorizeDrive(raw); const gateway = new RecoveryGateway(config); const postgres = new PgSnapshot(productionPgEnv(raw, ca));
    if (process.argv.includes("--check")) { await drive.preflight(config.target); const policy = await postgres.assertReadonlyRole(); const latest = await gateway.control("latest"); return { ready: true, policy, latestAgeHours: latest ? (Date.now() - Date.parse(latest.finished_at)) / 3600_000 : null }; }
    return await capture({ config, drive, gateway, postgres, directory });
  } finally { await rm(directory, { recursive: true, force: true }); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().then(() => console.log("Recovery operation completed; runtime details remain private.")).catch(error => { if (error.code === "SUPPORTED_PLATFORM_POLICY_REQUIRED") { console.error("::error title=Supported platform policy required::Backup scope or reachable managed capabilities need review. Readiness remains off; no complete recovery claim is made."); process.exitCode=1; return; } console.error("::error title=Recovery backup failed::Capture/preflight failed. No complete backup is claimed. Check isolated operator diagnostics; secrets and learner paths are never printed."); process.exitCode = 1; });
