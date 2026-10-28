export const REQUIRED_SCHEMAS = ["public", "auth", "storage", "supabase_migrations"];
export const DEFINITION_SCHEMAS = ["extensions"];
export const PROVIDER_SCHEMAS = ["graphql", "graphql_public", "realtime", "supabase_functions", "vault", "pgsodium", "pgsodium_masks", "net", "cron"];
export const REVIEWED_EXTENSIONS = ["plpgsql", "pgcrypto", "uuid-ossp", "pg_stat_statements", "pg_graphql", "supabase_vault", "pgsodium", "pg_net", "pg_cron", "vector"];
export class PlatformPolicyRequired extends Error { constructor(reason) { super(`supported_platform_policy_required:${reason}`); this.code="SUPPORTED_PLATFORM_POLICY_REQUIRED"; } }
export function assertScope(inventory, selected = [...REQUIRED_SCHEMAS, ...DEFINITION_SCHEMAS]) {
  if (!inventory || !Array.isArray(inventory.schemas) || !Array.isArray(inventory.extensions) || !Array.isArray(inventory.relations) || !Array.isArray(inventory.requiredData)) throw new PlatformPolicyRequired("scope_inventory_missing");
  for (const schema of inventory.schemas) if (!selected.includes(schema) && !PROVIDER_SCHEMAS.includes(schema)) throw new PlatformPolicyRequired("unreviewed_schema");
  for (const extension of inventory.extensions) if (!REVIEWED_EXTENSIONS.includes(extension.name)) throw new PlatformPolicyRequired("unreviewed_extension");
  if (inventory.relations.some(relation=>DEFINITION_SCHEMAS.includes(relation.schema))) throw new PlatformPolicyRequired("extension_definition_namespace_contains_data");
  if (inventory.relations.some(relation=>relation.kind === "f")) throw new PlatformPolicyRequired("foreign_table_data_requires_review");
  for (const relation of inventory.relations) if (!selected.includes(relation.schema) && !relation.extensionOwned && !/^supabase_/.test(relation.owner)) throw new PlatformPolicyRequired("app_relation_outside_scope");
  for (const item of inventory.requiredData) if (!selected.includes(item.relation.split(".")[0]) && (item.queryable!==true || item.count!==0)) throw new PlatformPolicyRequired("nonempty_or_unreadable_provider_configuration");
  return { schemas: inventory.schemas, extensions: inventory.extensions, managedResiduals: inventory.managedResiduals ?? [] };
}
