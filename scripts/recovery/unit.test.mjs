import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { authorizeDrive } from "./drive.mjs";
import { verifiedUpload, sha256 } from "./io.mjs";
import { productionPgEnv } from "./postgres.mjs";
import { configuration, capture } from "./backup.mjs";
import { keepRecoveryPoints } from "./retention.mjs";
import { fakeDrive } from "./fake-drive.test-support.mjs";
const raw = { RECOVERY_OAUTH_PUBLISHING_STATUS: "production", RECOVERY_DRIVE_CLIENT_ID: "fixture-client", RECOVERY_DRIVE_CLIENT_SECRET: "fixture-secret", RECOVERY_DRIVE_REFRESH_TOKEN: "fixture-refresh" };
test("Drive actual HTTP preflight enforces owner and inaccessible recovery identity", async () => {
 const fake=await fakeDrive(); try {
  const drive=await authorizeDrive(raw,fake.fetcher); drive.expiresAt=0; await drive.preflight(fake.config); assert.ok(drive.expiresAt>Date.now());
  fake.setOwner("other@example.invalid"); await assert.rejects(drive.preflight(fake.config),/owner mismatch/);
  fake.setOwner(fake.config.ownerEmail); fake.exposeKey(); await assert.rejects(drive.preflight(fake.config),/recovery identity/);
  await assert.rejects(authorizeDrive({...raw,RECOVERY_OAUTH_PUBLISHING_STATUS:"testing"},fake.fetcher),/Testing/);
 } finally {await fake.close();}
});
test("Drive actual HTTP resumable upload recovers stored bytes after lost response and verifies readback", async () => {
 const fake=await fakeDrive(), directory=await mkdtemp(join(tmpdir(),"recovery-http-")); try {
  const drive=await authorizeDrive(raw,fake.fetcher), bytes=randomBytes(9*1024*1024), file=join(directory,"cipher.bin"); await writeFile(file,bytes); fake.retryOnce();
  const result=await verifiedUpload(drive,file,{name:"fixture",parents:["folder_archive"],appProperties:{jodjamBackup:"1",kind:"object"}});
  assert.equal(result.cipherSha256,sha256(bytes)); assert.equal(fake.retried(),true); assert.deepEqual(fake.files.get(result.id).bytes,bytes);
  const corrupt={...drive,upload:drive.upload.bind(drive),media:async()=>new Response(Buffer.from("corrupt"))};
  await assert.rejects(verifiedUpload(corrupt,file,{name:"fixture",parents:["folder_archive"]}),/readback mismatch/);
 } finally {await fake.close();await rm(directory,{recursive:true,force:true});}
});
test("production connection and workflow settings reject weakened TLS, pooler and untrusted branches", () => {
 assert.throws(()=>configuration({RECOVERY_BACKUP_ENABLED:"true",GITHUB_ACTIONS:"true",GITHUB_REF:"refs/heads/other"}),/trusted main/);
 const connection=new URL("postgresql://host.pooler.supabase.com:5432/postgres"); connection.username="security_backup_reader.abcdefghijklmnopqrst"; const fixtureCredential="fixture"; connection.password=fixtureCredential;
 const base={RECOVERY_DATABASE_URL:connection.href,RECOVERY_DATABASE_ROLE:"security_backup_reader",RECOVERY_SOURCE_PROJECT_REF:"abcdefghijklmnopqrst"};
 connection.port="6543"; assert.throws(()=>productionPgEnv({...base,RECOVERY_DATABASE_URL:connection.href},"/ca"),/session pooler/);
 connection.port="5432";connection.search="sslmode=require";assert.throws(()=>productionPgEnv({...base,RECOVERY_DATABASE_URL:connection.href},"/ca"),/dedicated backup role/);
 const settings=productionPgEnv(base,"/ca");assert.equal(settings.env.PGSSLMODE,"verify-full");
});
test("retention preserves seven daily points, four weekly points and newest point", () => {
 const points=Array.from({length:60},(_,i)=>({file:{id:`point-${i}`},seal:{createdAt:new Date(Date.UTC(2026,9,27)-i*12*3600_000).toISOString()}}));
 const keep=keepRecoveryPoints(points); assert.ok(keep.has("point-0")); assert.ok(keep.size>=7&&keep.size<=11);
 for(const index of [0,1,3,5,7,9,11])assert.ok(keep.has(`point-${index}`));
});
test("retention refuses a foreign inventory before any deletion", async () => {
 const { retain } = await import("./retention.mjs");let deleted=0;
 await assert.rejects(retain({remove:async()=>{deleted++;}},[{id:"foreign_file_id",parents:["different_folder"]}],"unused","folder_archive"),/folder mismatch/);
 assert.equal(deleted,0);
});
test("capture scope refuses unknown schemas/extensions and nonempty provider configuration", async () => {
 const { assertScope }=await import("./scope-policy.mjs");
 const base={schemas:["public","auth","storage","supabase_migrations","extensions"],extensions:[{name:"pgcrypto",version:"fixture"}],relations:[],requiredData:[{relation:"vault.secrets",count:0,queryable:true}]};
 assert.doesNotThrow(()=>assertScope(base));
 for(const change of [
  c=>c.schemas.push("unreviewed_app"),c=>c.extensions.push({name:"unknown_extension"}),
  c=>c.requiredData[0].count=1,c=>c.requiredData[0].queryable=false,
  c=>c.relations.push({schema:"vault",owner:"postgres",extensionOwned:false}),
  c=>c.relations.push({schema:"public",owner:"postgres",extensionOwned:false,kind:"f"}),
 ]){const c=structuredClone(base);change(c);assert.throws(()=>assertScope(c),error=>error.code==="SUPPORTED_PLATFORM_POLICY_REQUIRED");}
});
test("optional Drive SHA uses actual cipher readback and source-project mismatch fails closed", async () => {
 const { verifyStoredCipher }=await import("./io.mjs"),{ RecoveryGateway }=await import("./backup.mjs");
 const bytes=Buffer.from("fixture-cipher"), expected=sha256(bytes), file={id:"fixture_file_0000",size:String(bytes.length)};
 await verifyStoredCipher({media:async()=>new Response(bytes)},file,expected,bytes.length);
 await assert.rejects(verifyStoredCipher({media:async()=>new Response(Buffer.from("wrong-cipher!!"))},file,expected,bytes.length));
 const gateway=new RecoveryGateway({origin:"https://learn.example.invalid",secret:"fixture-only",sourceProject:"expected",fetcher:async()=>Response.json({sourceProject:"different",run:null})});
 await assert.rejects(gateway.control("latest"),/project mismatch/);
});

test("an overdue deletion fence refuses capture before any database export or object download", async () => {
 const actions=[]; let exported=false,downloaded=false;
 const lease={id:"fixture",state:"capturing",started_at:new Date().toISOString(),lease_until:new Date(Date.now()+60000).toISOString(),draining:true,overdueDeletions:1};
 const gateway={control:async(action)=>{actions.push(action);return action==='latest'?null:lease;},object:async()=>{downloaded=true;}};
 const postgres={config:{},assertReadonlyRole:async()=>{exported=true;},begin:async()=>{exported=true;},close:async()=>{}};
 await assert.rejects(capture({config:{target:{}},drive:{preflight:async()=>{},list:async()=>[]},gateway,postgres,directory:'/unused'}),/operator reconciliation required/);
 assert.deepEqual(actions,['latest','begin','fail']);assert.equal(exported,false);assert.equal(downloaded,false);
});

test("health warns at eighteen hours and becomes critical at twenty-four without disclosing runtime details", async () => {
 const { recoveryHealth }=await import("./health.mjs"), now=Date.UTC(2026,9,27,12);
 const at=hours=>({state:"sealed",finished_at:new Date(now-hours*3600000).toISOString()});
 assert.equal(recoveryHealth(at(17.99),now),"healthy");assert.equal(recoveryHealth(at(18),now),"warning");assert.equal(recoveryHealth(at(23.99),now),"warning");assert.equal(recoveryHealth(at(24),now),"critical");
 for(const value of[null,{state:"capturing",finished_at:new Date(now).toISOString()},{state:"sealed",finished_at:"invalid"},at(-1)])assert.equal(recoveryHealth(value,now),"critical");
});
