import { spawn } from "node:child_process";
import { join } from "node:path";
import { REQUIRED_SCHEMAS, DEFINITION_SCHEMAS, assertScope, PlatformPolicyRequired } from "./scope-policy.mjs";
import { StringDecoder } from "node:string_decoder";
import { run } from "./io.mjs";
export function productionPgEnv(raw = process.env, caPath) {
  if (!raw.RECOVERY_DATABASE_URL || !caPath || !raw.RECOVERY_DATABASE_ROLE) throw new Error("dedicated database credentials and CA required");
  const url = new URL(raw.RECOVERY_DATABASE_URL);
  if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname.endsWith(".pooler.supabase.com") || url.port !== "5432" || url.pathname !== "/postgres" || !url.password) throw new Error("verified-TLS session pooler required");
  if (url.search || url.username !== `${raw.RECOVERY_DATABASE_ROLE}.${raw.RECOVERY_SOURCE_PROJECT_REF}` || !/^security_backup_reader$/.test(raw.RECOVERY_DATABASE_ROLE)) throw new Error("dedicated backup role required");
  const client = raw.RECOVERY_PG_BIN || "/usr/lib/postgresql/17/bin";
  return { bin: client, expectedRole: raw.RECOVERY_DATABASE_ROLE, env: { PATH: process.env.PATH, LC_ALL: "C", PGHOST: url.hostname, PGPORT: url.port,
    PGDATABASE: url.pathname.slice(1), PGUSER: decodeURIComponent(url.username), PGPASSWORD: decodeURIComponent(url.password), PGSSLMODE: "verify-full", PGSSLROOTCERT: caPath,
    PGCONNECT_TIMEOUT: "15", PGOPTIONS: "-c default_transaction_read_only=on -c statement_timeout=600000 -c lock_timeout=10000" } };
}
export class PgSnapshot {
  constructor(config) { this.config = config; this.schemas = config.schemas ?? [...REQUIRED_SCHEMAS, ...DEFINITION_SCHEMAS]; if (this.schemas.length>20 || this.schemas.some(schema=>!/^[_a-z][_a-z0-9]*$/.test(schema))) throw new Error("reviewed schema identifiers required"); }
  command(name) { return join(this.config.bin, name); }
  async query(sql) { return run(this.command("psql"), ["-X", "-qAt", "-w", "-v", "ON_ERROR_STOP=1"], { env: this.config.env, input: sql, signal: this.config.signal }); }
  async assertReadonlyRole() {
    const result = JSON.parse(await this.query(`select jsonb_build_object('role',current_user,'super',r.rolsuper,'createdb',r.rolcreatedb,'createrole',r.rolcreaterole,'replication',r.rolreplication,'bypass',r.rolbypassrls,'readonly',current_setting('default_transaction_read_only'),
      'admin',pg_has_role(current_user,'postgres','MEMBER'),
      'reader',exists(select 1 from pg_roles where rolname=current_user),
      'unexpectedMembership',exists(select 1 from pg_auth_members m join pg_roles g on g.oid=m.roleid where m.member=r.oid),
      'createSchema',has_database_privilege(current_user,current_database(),'CREATE') or exists(select 1 from pg_namespace n where has_schema_privilege(current_user,n.oid,'CREATE')),
      'writes',exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=any(array[${this.schemas.map(schema=>"'"+schema+"'").join(",")}]) and c.relkind in ('r','p','v','f') and (has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') or has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES'))),
      'statefulFunctions',exists(select 1 from pg_proc f join pg_namespace n on n.oid=f.pronamespace where n.nspname in ('pg_catalog','net') and n.nspname='net' and has_schema_privilege(current_user,n.oid,'USAGE') and has_function_privilege(current_user,f.oid,'EXECUTE')),
      'largeObjects',exists(select 1 from pg_largeobject_metadata l where not (pg_has_role(current_user,l.lomowner,'USAGE') or exists(select 1 from aclexplode(coalesce(l.lomacl,acldefault('L',l.lomowner))) a where a.privilege_type='SELECT' and case when a.grantee=0 then true else pg_has_role(current_user,a.grantee,'USAGE') end))),
      'unknownDefiners',exists(select 1 from pg_proc f join pg_namespace n on n.oid=f.pronamespace where n.nspname<>'pg_catalog' and f.prosecdef and has_schema_privilege(current_user,n.oid,'USAGE') and has_function_privilege(current_user,f.oid,'EXECUTE') and f.oid is distinct from to_regprocedure('public.security_backup_scope_inventory()')),
      'scopeProof',coalesce(has_function_privilege(current_user,to_regprocedure('public.security_backup_scope_inventory()'),'EXECUTE'),false),
      'secretSchema',exists(select 1 from pg_namespace n where n.nspname in ('vault','cron','pgsodium','pgsodium_masks') and has_schema_privilege(current_user,n.oid,'USAGE') and n.nspname<>all(array[${this.schemas.map(schema=>"'"+schema+"'").join(",")}])) ,
      'netTable',exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='net' and has_schema_privilege(current_user,n.oid,'USAGE') and (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE') or has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE'))),
      'readCoverage',not exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=any(array[${this.schemas.map(schema=>"'"+schema+"'").join(",")}]) and c.relkind in ('r','p','m') and (not has_schema_privilege(current_user,n.oid,'USAGE') or not has_table_privilege(current_user,c.oid,'SELECT'))),
      'sequences',exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind='S' and n.nspname=any(array[${this.schemas.map(schema=>"'"+schema+"'").join(",")}]) and has_sequence_privilege(current_user,c.oid,'USAGE,UPDATE')),
      'required',exists(select 1 from pg_namespace where nspname='supabase_migrations') and exists(select 1 from pg_namespace where nspname='auth') and exists(select 1 from pg_namespace where nspname='storage')) from pg_roles r where r.rolname=current_user;`));
    if (result.role !== this.config.expectedRole || result.super || result.createdb || result.createrole || result.replication || !result.bypass || result.readonly !== "on" || result.admin || !result.reader || result.unexpectedMembership || result.createSchema || result.writes || result.sequences || result.largeObjects || !result.required) throw new Error("backup role/read coverage readiness failed");
    if (!result.readCoverage || !result.scopeProof) throw new PlatformPolicyRequired("selected_schema_read_grants_or_metadata_proof_incomplete");
    if (result.secretSchema || result.unknownDefiners) throw new PlatformPolicyRequired("unreviewed_secret_schema_or_definer");
    if (result.statefulFunctions || (result.netTable && !this.schemas.includes("net"))) throw new PlatformPolicyRequired("reachable_managed_pg_net_capabilities");
    return this.auditScope();
  }
  async auditScope() {
    const inventory = JSON.parse(await this.query(`select jsonb_build_object(
      'schemas',(select coalesce(jsonb_agg(nspname),'[]') from pg_namespace where nspname not in ('pg_catalog','information_schema') and left(nspname,3)<>'pg_'),
      'extensions',(select coalesce(jsonb_agg(jsonb_build_object('name',extname,'version',extversion)),'[]') from pg_extension),
      'relations',(select coalesce(jsonb_agg(jsonb_build_object('schema',n.nspname,'kind',c.relkind,'owner',r.rolname,'extensionOwned',exists(select 1 from pg_depend d where d.classid='pg_class'::regclass and d.objid=c.oid and d.deptype='e'))),'[]') from pg_class c join pg_namespace n on n.oid=c.relnamespace join pg_roles r on r.oid=c.relowner where c.relkind in ('r','p','m','f') and n.nspname not in ('pg_catalog','information_schema') and left(n.nspname,3)<>'pg_'),
      'requiredData',public.security_backup_scope_inventory(),
      'managedResiduals',jsonb_build_array('PUBLIC large-object allocation may consume resources; no application-row write is granted'));
    `));
    return assertScope(inventory, this.schemas);
  }
  async begin() {
    const child = spawn(this.command("psql"), ["-X", "-qAt", "-w", "-v", "ON_ERROR_STOP=1"], { env: this.config.env, signal: this.config.signal, stdio: ["pipe", "pipe", "pipe"] });
    this.child = child; this.objects = []; const decoder = new StringDecoder("utf8"); let buffer = "", bytes = 0, ready = false;
    child.stdin.on("error", () => {});
    this.closed = new Promise(resolve => child.once("close", resolve));
    child.stderr.resume();
    const result = new Promise((resolve, reject) => {
      const fail = () => reject(new Error("snapshot holder failed")); child.on("error", fail);
      child.on("close", code => { if (!ready || code !== 0) fail(); });
      child.stdout.on("data", chunk => {
        bytes += chunk.length;
        if (bytes > 128 * 1024 * 1024) { child.kill(); fail(); return; }
        buffer += decoder.write(chunk);
        for (;;) {
          const end = buffer.indexOf("\n"); if (end < 0) break;
          const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
          try {
            if (line.startsWith("SNAPSHOT:")) { this.snapshot = line.slice(9); if (!/^[A-Fa-f0-9]+-[A-Fa-f0-9]+-\d+$/.test(this.snapshot)) throw new Error(); }
            else if (line.startsWith("SCOPE:")) { const requiredData=JSON.parse(line.slice(6)); assertScope({schemas:this.schemas,extensions:[],relations:[],requiredData},this.schemas); }
            else if (line === "MANIFEST_DONE") { if (!this.snapshot) throw new Error(); ready = true; resolve(this); }
            else if (line) {
              const object = JSON.parse(line);
              if (!/^[a-z0-9-]{1,100}$/.test(object.bucket) || typeof object.path !== "string" || !object.path || object.path.length > 2048 || object.path.includes("\0") || !/^\d+$/.test(object.size) || Number(object.size) > 512 * 1024 * 1024 || !object.id || !object.updatedAt || this.objects.length >= 100_000) throw new Error();
              this.objects.push({ ...object, size: Number(object.size) });
            }
          } catch { child.kill(); reject(new Error("storage snapshot manifest invalid")); }
        }
      });
    });
    child.stdin.write(`begin transaction isolation level repeatable read read only;\nselect 'SNAPSHOT:'||pg_export_snapshot();\nselect 'SCOPE:'||public.security_backup_scope_inventory()::text;\nselect jsonb_build_object('bucket',bucket_id,'path',name,'size',metadata->>'size','id',id::text,'updatedAt',updated_at::text,'etag',coalesce(metadata->>'eTag',metadata->>'etag')) from storage.objects order by bucket_id,name;\n\\echo MANIFEST_DONE\n`);
    return result;
  }
  async dump(directory) {
    if (!this.snapshot) throw new Error("snapshot not active");
    await this.auditScope();
    await run(this.command("pg_dump"), ["--format=custom", "--large-objects", ...this.schemas.map(schema=>`--schema=${schema}`), `--snapshot=${this.snapshot}`, "--no-password", `--file=${join(directory, "database.dump")}`], { env: this.config.env, signal: this.config.signal });
    await run(this.command("pg_dumpall"), ["--roles-only", "--no-role-passwords", "--no-password", `--database=${this.config.env.PGDATABASE}`], { env: this.config.env, signal: this.config.signal, output: join(directory, "roles.sql") });
  }
  async close() {
    if (!this.child) return;
    const child = this.child; this.child = null;
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.stdin.end("rollback;\n"); await this.closed;
  }
}
