import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createReadStream, createWriteStream } from "node:fs";
import { open } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
export const sha256 = value => createHash("sha256").update(value).digest("hex");
export const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
export async function fileDigest(path) {
  const hash = createHash("sha256"); let size = 0;
  for await (const chunk of createReadStream(path)) { hash.update(chunk); size += chunk.length; }
  return { sha256: hash.digest("hex"), size };
}
export function run(command, args, { env = { PATH: process.env.PATH, LC_ALL: "C" }, input, signal, output, maxOutput = 4 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, signal, stdio: ["pipe", output ? "pipe" : "pipe", "pipe"] });
    const chunks = []; let size = 0, outputFailure;
    const sink = output ? createWriteStream(output, { mode: 0o600, flags: "wx" }) : null;
    if (sink) pipeline(child.stdout, sink).catch(error => { outputFailure = error; child.kill(); });
    else child.stdout.on("data", data => { size += data.length; if (size > maxOutput) child.kill(); else chunks.push(data); });
    // Upstream diagnostics can include connection passwords/learner paths. Never surface them.
    child.stderr.resume(); child.on("error", () => reject(new Error(`${command.split("/").at(-1)} failed`)));
    child.on("close", async code => {
      if (sink && !sink.closed) await new Promise(resolve => sink.once("close", resolve));
      if (code !== 0 || size > maxOutput || outputFailure) reject(new Error(`${command.split("/").at(-1)} failed`));
      else resolve(Buffer.concat(chunks).toString("utf8"));
    }); child.stdin.on("error", () => {}); child.stdin.end(input);
  });
}
export async function jsonResponse(response, maxBytes = 4 * 1024 * 1024) {
  if (!response.ok || !response.body) throw new Error(`remote request failed (${response.status})`);
  const chunks = []; let size = 0;
  for await (const chunk of response.body) { size += chunk.length; if (size > maxBytes) throw new Error("remote JSON too large"); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new Error("remote JSON invalid"); }
}
export async function download(response, target, { expectedSize, maxBytes = 512 * 1024 * 1024, signal } = {}) {
  if (!response.ok || !response.body) throw new Error(`download failed (${response.status})`);
  const handle = await open(target, "wx", 0o600); const hash = createHash("sha256"); let size = 0;
  try {
    for await (const chunk of response.body) {
      signal?.throwIfAborted(); size += chunk.length;
      if (size > maxBytes || (expectedSize !== undefined && size > expectedSize)) throw new Error("download size exceeded");
      hash.update(chunk); await handle.writeFile(chunk);
    }
  } finally { await handle.close(); }
  if (expectedSize !== undefined && size !== expectedSize) throw new Error("download size mismatch");
  return { size, sha256: hash.digest("hex") };
}
export async function responseDigest(response, maxBytes = Number.MAX_SAFE_INTEGER) {
  if (!response.ok || !response.body) throw new Error("cipher readback unavailable");
  const hash = createHash("sha256"); let size = 0;
  for await (const chunk of response.body) { size += chunk.length; if (size > maxBytes) throw new Error("cipher readback too large"); hash.update(chunk); }
  return { size, sha256: hash.digest("hex") };
}
export async function encrypt(input, output, recipient, { age = "age", signal } = {}) {
  if (!/^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$/.test(recipient)) throw new Error("age public recipient required");
  await run(age, ["--encrypt", "--recipient", recipient, "--output", output, input], { signal });
  return fileDigest(output);
}
export async function verifiedUpload(drive, path, metadata) {
  const digest = await fileDigest(path); const file = await drive.upload(path, metadata);
  const actual = await responseDigest(await drive.media(file.id), digest.size);
  if (actual.sha256 !== digest.sha256 || actual.size !== digest.size) throw new Error("Drive cipher readback mismatch");
  return { id: file.id, cipherSha256: digest.sha256, cipherSize: digest.size };
}

/** Drive's SHA256 field is optional. When absent, prove the bytes again instead of guessing or trusting names. */
export async function verifyStoredCipher(drive, file, expectedSha, expectedSize) {
  if (!/^[a-f0-9]{64}$/.test(expectedSha) || Number(file.size) !== Number(expectedSize)) throw new Error("stored cipher receipt invalid");
  if (file.sha256Checksum) { if (file.sha256Checksum !== expectedSha) throw new Error("stored cipher checksum mismatch"); return; }
  const actual = await responseDigest(await drive.media(file.id), Number(expectedSize));
  if (actual.sha256 !== expectedSha || actual.size !== Number(expectedSize)) throw new Error("stored cipher readback mismatch");
}
