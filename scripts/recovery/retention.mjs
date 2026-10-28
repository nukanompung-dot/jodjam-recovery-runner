import { jsonResponse, verifyStoredCipher } from "./io.mjs";
const id = /^[A-Za-z0-9_-]{8,200}$/;
const sha = /^[a-f0-9]{64}$/;
export function validateSeal(seal) {
  if (seal?.version !== 1 || !/^[0-9a-f-]{36}$/.test(seal.runId ?? "") || !Number.isFinite(Date.parse(seal.createdAt)) || !id.test(seal.archive?.id ?? "") || !sha.test(seal.archive.cipherSha256 ?? "") || !sha.test(seal.manifestSha256 ?? "") || !Array.isArray(seal.objects) || seal.objects.length > 100_000 || seal.objects.some(object => !id.test(object.id ?? "") || !sha.test(object.cipherSha256 ?? ""))) throw new Error("invalid sealed recovery point");
  return seal;
}
export function keepRecoveryPoints(points) {
  const ordered = [...points].sort((a, b) => Date.parse(b.seal.createdAt) - Date.parse(a.seal.createdAt));
  const days = new Set(), weeks = new Set(), keep = new Set();
  for (const point of ordered) {
    const day = point.seal.createdAt.slice(0, 10);
    const date = new Date(`${day}T00:00:00Z`); const delta = (date.getUTCDay() + 6) % 7; date.setUTCDate(date.getUTCDate() - delta); const week = date.toISOString().slice(0, 10);
    if ((!days.has(day) && days.size < 7) || (!weeks.has(week) && weeks.size < 4)) keep.add(point.file.id);
    if (days.size < 7) days.add(day); if (weeks.size < 4) weeks.add(week);
  }
  if (ordered[0]) keep.add(ordered[0].file.id);
  return keep;
}
export async function retain(drive, files, newestRunId, folderId) {
  const inventory = new Map(files.map(file => [file.id, file]));
  if (!folderId || files.some(file => !id.test(file.id) || !file.parents?.includes(folderId))) throw new Error("retention inventory folder mismatch");
  const points = [];
  for (const file of files.filter(file => file.appProperties?.kind === "seal" && file.appProperties?.committed === "1")) {
    const seal = validateSeal(await jsonResponse(await drive.media(file.id), 32 * 1024 * 1024));
    if (file.appProperties.runId !== seal.runId) throw new Error("seal identity mismatch");
    const archive = inventory.get(seal.archive.id);
    if (archive?.appProperties?.kind !== "snapshot" || archive.appProperties.runId !== seal.runId) throw new Error("archive inventory binding mismatch");
    await verifyStoredCipher(drive, archive, seal.archive.cipherSha256, seal.archive.cipherSize);
    for (const object of seal.objects) { const stored = inventory.get(object.id); if (stored?.appProperties?.kind !== "object") throw new Error("object inventory binding mismatch"); await verifyStoredCipher(drive,stored,object.cipherSha256,object.cipherSize); }
    points.push({ file, seal });
  }
  if (!points.some(point => point.seal.runId === newestRunId)) throw new Error("newest sealed point absent; retention refused");
  const keep = keepRecoveryPoints(points), refs = new Set();
  for (const point of points.filter(point => keep.has(point.file.id))) { refs.add(point.seal.archive.id); refs.add(point.file.id); for (const object of point.seal.objects) refs.add(object.id); }
  // Delete obsolete seals/archives first, then unreferenced old cipher objects. Never evict under quota pressure.
  for (const point of points.filter(point => !keep.has(point.file.id))) { await drive.remove(point.file.id); if (!refs.has(point.seal.archive.id)) await drive.remove(point.seal.archive.id); }
  for (const file of files) if (["object", "snapshot"].includes(file.appProperties?.kind) && !refs.has(file.id) && Date.parse(file.createdTime) < Date.now() - 2 * 86400_000) await drive.remove(file.id);
  return { retained: keep.size, points: points.length };
}
