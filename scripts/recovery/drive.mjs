import { open, stat } from "node:fs/promises";
import { jsonResponse, delay } from "./io.mjs";
const DRIVE = "https://www.googleapis.com";
const FILE = "https://www.googleapis.com/auth/drive.file";
const idPattern = /^[A-Za-z0-9_-]{8,200}$/;
export class Drive {
  constructor({ token, expiresAt = Infinity, refresh, fetcher = fetch }) { this.token = token; this.expiresAt = expiresAt; this.refresh = refresh; this.fetcher = fetcher; }
  async accessToken(force = false) {
    if (this.refresh && (force || this.expiresAt < Date.now() + 60_000)) {
      if (!this.refreshing) this.refreshing = this.refresh().then(result => { this.token=result.token; this.expiresAt=result.expiresAt; }).finally(()=>{this.refreshing=null;});
      await this.refreshing;
    }
    return this.token;
  }
  async authenticated(url, init = {}, redirect = "error") {
    const send = async force => this.fetcher(url, { ...init, redirect, headers: { ...init.headers, Authorization: `Bearer ${await this.accessToken(force)}` }, signal: AbortSignal.timeout(60_000) });
    const response=await send(false);
    return response.status===401 && this.refresh ? send(true) : response;
  }
  async request(path, init = {}) {
    if (!path.startsWith("/drive/v3/") && !path.startsWith("/upload/drive/v3/")) throw new Error("fixed Drive path required");
    return this.authenticated(`${DRIVE}${path}`, init);
  }
  async json(path, init) { return jsonResponse(await this.request(path, init)); }
  async preflight(config, requiredBytes = 0) {
    const about = await this.json("/drive/v3/about?fields=user(emailAddress),storageQuota");
    if (about.user?.emailAddress?.toLowerCase() !== config.ownerEmail.toLowerCase()) throw new Error("Drive owner mismatch");
    const limit = Number(about.storageQuota?.limit), used = Number(about.storageQuota?.usage);
    if (!Number.isSafeInteger(limit) || !Number.isSafeInteger(used) || limit - used < Math.max(requiredBytes, 100 * 1024 * 1024)) throw new Error("Drive quota/headroom insufficient");
    for (const key of ["archiveFolderId", "recoveryFolderId", "recoveryKeyFileId"]) if (!idPattern.test(config[key] ?? "")) throw new Error("Drive destination configuration missing");
    if (config.archiveFolderId === config.recoveryFolderId || config.recoveryKeyReadbackVerified !== true) throw new Error("recovery key verification required");
    const folder = await this.json(`/drive/v3/files/${config.archiveFolderId}?fields=id,mimeType,ownedByMe,owners(emailAddress),capabilities(canAddChildren)`);
    if (folder.mimeType !== "application/vnd.google-apps.folder" || !folder.ownedByMe || !folder.capabilities?.canAddChildren || folder.owners?.length !== 1 || folder.owners[0].emailAddress?.toLowerCase() !== config.ownerEmail.toLowerCase()) throw new Error("private owned archive folder required");
    const permissions = await this.json(`/drive/v3/files/${config.archiveFolderId}/permissions?fields=permissions(type,role,emailAddress),nextPageToken&pageSize=100`);
    if (permissions.nextPageToken || !permissions.permissions?.length || permissions.permissions.some(permission => permission.type !== "user" || permission.role !== "owner" || permission.emailAddress?.toLowerCase() !== config.ownerEmail.toLowerCase())) throw new Error("archive folder is shared");
    for (const id of [config.recoveryFolderId, config.recoveryKeyFileId]) {
      const response = await this.request(`/drive/v3/files/${id}?fields=id`);
      if (![403, 404].includes(response.status)) throw new Error("unattended credential can access recovery identity");
    }
    return { available: limit - used };
  }
  async list(folder) {
    if (!idPattern.test(folder)) throw new Error("invalid folder");
    const files = []; let page;
    do {
      const query = new URLSearchParams({ q: `'${folder}' in parents and trashed=false and appProperties has { key='jodjamBackup' and value='1' }`, fields: "files(id,name,size,sha256Checksum,appProperties,createdTime,parents),nextPageToken", pageSize: "1000", ...(page ? { pageToken: page } : {}) });
      const result = await this.json(`/drive/v3/files?${query}`);
      if (!Array.isArray(result.files) || files.length + result.files.length > 200_000) throw new Error("Drive inventory invalid/too large");
      files.push(...result.files); page = result.nextPageToken;
    } while (page);
    return files;
  }
  async media(id) { if (!idPattern.test(id)) throw new Error("invalid Drive ID"); return this.request(`/drive/v3/files/${id}?alt=media`); }
  async metadata(id) { if (!idPattern.test(id)) throw new Error("invalid Drive ID"); return this.json(`/drive/v3/files/${id}?fields=id,size,sha256Checksum,appProperties,parents`); }
  async markCommitted(id) { if (!idPattern.test(id)) throw new Error("invalid Drive ID"); return this.json(`/drive/v3/files/${id}?fields=id`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ appProperties: { committed: "1" } }) }); }
  async remove(id) { if (!idPattern.test(id)) throw new Error("invalid Drive ID"); const response = await this.request(`/drive/v3/files/${id}`, { method: "DELETE" }); if (response.status !== 204) throw new Error("Drive retention deletion failed"); }
  async upload(path, metadata) {
    const size = (await stat(path)).size;
    if (!Number.isSafeInteger(size) || size < 1) throw new Error("empty cipher upload refused");
    const start = await this.request("/upload/drive/v3/files?uploadType=resumable&fields=id,size,sha256Checksum,appProperties,parents", {
      method: "POST", headers: { "Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Type": "application/octet-stream", "X-Upload-Content-Length": String(size) }, body: JSON.stringify(metadata),
    });
    const session = start.headers.get("location");
    if (!start.ok || !session) throw new Error("Drive resumable session failed");
    const url = new URL(session);
    if (url.origin !== DRIVE || !(url.pathname === "/upload/drive/v3/files" || url.pathname.startsWith("/upload/drive/v3/files/"))) throw new Error("untrusted Drive upload session");
    const handle = await open(path, "r"); let offset = 0, retries = 0;
    const send = init => this.authenticated(session, init, "manual");
    const progress = response => {
      const match = /^bytes=0-(\d+)$/.exec(response.headers.get("range") ?? "");
      const next = match ? Number(match[1]) + 1 : 0;
      if (!Number.isSafeInteger(next) || next < offset || next > size) throw new Error("invalid upload progress");
      return next;
    };
    try {
      while (offset < size) {
        const buffer = Buffer.alloc(Math.min(8 * 1024 * 1024, size - offset));
        const read = await handle.read(buffer, 0, buffer.length, offset);
        if (read.bytesRead !== buffer.length) throw new Error("cipher changed while uploading");
        try {
          const response = await send({ method: "PUT", headers: { "Content-Length": String(buffer.length), "Content-Range": `bytes ${offset}-${offset + buffer.length - 1}/${size}` }, body: buffer });
          if (response.ok) { const file = await jsonResponse(response); if (!idPattern.test(file.id ?? "") || Number(file.size) !== size) throw new Error("Drive upload receipt invalid"); return file; }
          if (response.status === 308) { const next = progress(response); if (next <= offset) throw new Error("upload made no progress"); offset = next; retries = 0; continue; }
          if (response.status < 500 && response.status !== 429) throw new Error("Drive upload rejected");
        } catch { /* Query the resumable session before sending any bytes again. */ }
        if (++retries > 3) throw new Error("Drive resumable retry exhausted");
        await delay(250 * retries);
        const status = await send({ method: "PUT", headers: { "Content-Length": "0", "Content-Range": `bytes */${size}` } });
        if (status.ok) { const file = await jsonResponse(status); if (!idPattern.test(file.id ?? "") || Number(file.size) !== size) throw new Error("Drive upload receipt invalid"); return file; }
        if (status.status !== 308) throw new Error("Drive upload status unavailable");
        offset = progress(status);
      }
      throw new Error("Drive upload missing completion receipt");
    } finally { await handle.close(); }
  }
}
export async function authorizeDrive(raw = process.env, fetcher = fetch) {
  if (raw.RECOVERY_OAUTH_PUBLISHING_STATUS !== "production") throw new Error("OAuth Testing refresh tokens are not unattended-ready");
  if (!raw.RECOVERY_DRIVE_CLIENT_ID || !raw.RECOVERY_DRIVE_CLIENT_SECRET || !raw.RECOVERY_DRIVE_REFRESH_TOKEN) throw new Error("dedicated drive.file OAuth credentials required");
  const refresh = async () => {
    const response = await fetcher("https://oauth2.googleapis.com/token", { method: "POST", redirect: "error", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: raw.RECOVERY_DRIVE_CLIENT_ID, client_secret: raw.RECOVERY_DRIVE_CLIENT_SECRET, refresh_token: raw.RECOVERY_DRIVE_REFRESH_TOKEN, grant_type: "refresh_token" }), signal: AbortSignal.timeout(15_000) });
    const result = await jsonResponse(response, 64 * 1024);
    if (!result.access_token || result.token_type?.toLowerCase() !== "bearer" || result.scope?.trim() !== FILE || !Number.isFinite(result.expires_in) || result.expires_in<1) throw new Error("OAuth token scope/expiry must be exact drive.file");
    return { token: result.access_token, expiresAt: Date.now()+Math.min(result.expires_in,3600)*1000 };
  };
  return new Drive({ ...(await refresh()), refresh, fetcher });
}
