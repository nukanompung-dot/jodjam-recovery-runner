import http from "node:http";
import { createHash } from "node:crypto";
export async function fakeDrive() {
  const files = new Map(), uploads = new Map(); let sequence = 1000, owner = "owner@example.invalid", exposedKey = false, retryOnce = false, retried = false;
  const json = (res, code, data) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(data)); };
  const digest = bytes => createHash("sha256").update(bytes).digest("hex");
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost"); const chunks = []; for await (const data of req) chunks.push(data); const body = Buffer.concat(chunks);
    if (url.pathname === "/token") return json(res, 200, { access_token: "fixture-access", token_type: "Bearer", expires_in:3600, scope: "https://www.googleapis.com/auth/drive.file" });
    if (url.pathname === "/drive/v3/about") return json(res, 200, { user: { emailAddress: owner }, storageQuota: { limit: "15000000000", usage: "1000" } });
    if (url.pathname === "/drive/v3/files/folder_archive/permissions") return json(res, 200, { permissions: [{ type: "user", role: "owner", emailAddress: owner }] });
    if (url.pathname === "/drive/v3/files/folder_archive") return json(res, 200, { id: "folder_archive", mimeType: "application/vnd.google-apps.folder", ownedByMe: true, owners: [{ emailAddress: owner }], capabilities: { canAddChildren: true } });
    if (["/drive/v3/files/folder_recovery", "/drive/v3/files/recovery_key_file"].includes(url.pathname)) return json(res, exposedKey ? 200 : 404, exposedKey ? { id: "recovery_key_file" } : {});
    if (url.pathname === "/drive/v3/files" && req.method === "GET") return json(res, 200, { files: [...files.values()].map(({ bytes, ...file }) => file) });
    if (url.pathname === "/upload/drive/v3/files" && req.method === "POST") {
      const id = `fixture_file_${sequence++}`; uploads.set(id, { metadata: JSON.parse(body.toString()), bytes: Buffer.alloc(0) });
      res.writeHead(200, { Location: `https://www.googleapis.com/upload/drive/v3/files/${id}` }); return res.end();
    }
    if (url.pathname.startsWith("/upload/drive/v3/files/") && req.method === "PUT") {
      const id = url.pathname.split("/").at(-1), upload = uploads.get(id); if (!upload) return json(res, 404, {});
      const range = req.headers["content-range"];
      if (range?.startsWith("bytes */")) {
        const file = files.get(id); if (file) { const { bytes, ...metadata } = file; return json(res, 200, metadata); }
        res.writeHead(308, upload.bytes.length ? { Range: `bytes=0-${upload.bytes.length - 1}` } : {}); return res.end();
      }
      const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(range ?? "");
      if (!match || Number(match[1]) !== upload.bytes.length || Number(match[2]) + 1 !== upload.bytes.length + body.length) return json(res, 400, {});
      upload.bytes = Buffer.concat([upload.bytes, body]);
      if (retryOnce && !retried) { retried = true; return json(res, 500, {}); }
      if (upload.bytes.length === Number(match[3])) {
        const file = { ...upload.metadata, id, size: String(upload.bytes.length), sha256Checksum: digest(upload.bytes), createdTime: new Date().toISOString(), bytes: upload.bytes };
        files.set(id, file); const { bytes, ...metadata } = file; return json(res, 200, metadata);
      }
      res.writeHead(308, { Range: `bytes=0-${upload.bytes.length - 1}` }); return res.end();
    }
    const id = url.pathname.split("/").at(-1), file = files.get(id);
    if (file) {
      if (req.method === "DELETE") { files.delete(id); res.writeHead(204); return res.end(); }
      if (req.method === "PATCH") { const patch = JSON.parse(body.toString()); file.appProperties = { ...file.appProperties, ...patch.appProperties }; return json(res, 200, { id }); }
      if (url.searchParams.get("alt") === "media") { res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": file.bytes.length }); return res.end(file.bytes); }
      const { bytes, ...metadata } = file; return json(res, 200, metadata);
    }
    json(res, 404, {});
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { files, fetcher: (url, init) => { const parsed = new URL(url); if (!["www.googleapis.com", "oauth2.googleapis.com"].includes(parsed.hostname)) throw new Error("test Drive origin denied"); return fetch(`${origin}${parsed.pathname}${parsed.search}`, init); },
    config: { ownerEmail: owner, archiveFolderId: "folder_archive", recoveryFolderId: "folder_recovery", recoveryKeyFileId: "recovery_key_file", recoveryKeyReadbackVerified: true },
    setOwner: value => { owner = value; }, exposeKey: () => { exposedKey = true; }, retryOnce: () => { retryOnce = true; }, retried: () => retried,
    close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }),
  };
}
