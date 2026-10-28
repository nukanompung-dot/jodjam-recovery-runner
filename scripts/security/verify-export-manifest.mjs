import { readFile, readdir, lstat } from "node:fs/promises";import { resolve,join } from "node:path";import { createHash } from "node:crypto";import { pathToFileURL } from "node:url";
export const INVENTORY=["README.md",".github/workflows/ci.yml",".github/workflows/security-backup.yml",...["backup.mjs","drive.mjs","io.mjs","postgres.mjs","retention.mjs","scope-policy.mjs","health.mjs","unit.test.mjs","fake-drive.test-support.mjs"].map(name=>`scripts/recovery/${name}`),...["verify-ci-protection.mjs","verify-ci-protection.test.mjs","verify-export-manifest.mjs","verify-export-manifest.test.mjs"].map(name=>`scripts/security/${name}`)].sort();
async function inventory(dir,prefix=""){const result=[];for(const name of await readdir(dir)){if(!prefix&&name===".git")continue;const path=prefix+name,entry=await lstat(join(dir,name));if(entry.isSymbolicLink())throw new Error("public_inventory_symlink");if(entry.isDirectory())result.push(...await inventory(join(dir,name),path+"/"));else if(entry.isFile())result.push(path);else throw new Error("public_inventory_special_file");}return result.sort();}
export async function verifyExport(root=process.cwd()){
 const manifest=JSON.parse(await readFile(join(root,"public-runner-manifest.json"),"utf8"));
 if(manifest.version!==1||!Array.isArray(manifest.files)||!/^[a-f0-9]{40}$/.test(manifest.sourceCommit??""))throw new Error("public_manifest_invalid");
 if(JSON.stringify(manifest.files.map(file=>file.path).sort())!==JSON.stringify(INVENTORY)||JSON.stringify(await inventory(root))!==JSON.stringify([...INVENTORY,"public-runner-manifest.json"].sort()))throw new Error("public_inventory_mismatch");
 for(const row of manifest.files){const bytes=await readFile(join(root,row.path));if(bytes.length!==row.bytes||createHash("sha256").update(bytes).digest("hex")!==row.sha256)throw new Error("public_manifest_mismatch");}
 return true;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){try{await verifyExport();console.log("Public code inventory verified.");}catch{console.error("Public package inventory refused; do not publish app, runtime data, SQL, restore code or credentials.");process.exitCode=1;}}
