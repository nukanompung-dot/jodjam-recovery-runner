/** Inspection is an accidental-rollout guard. Server rules and the human owner remain authoritative. */
import { pathToFileURL } from 'node:url';
const CHECK='public-runner-tests', APP_ID=15368;
export function assertTrustedAutomation(branch,environment,policies,{repository,customRules,sourceSha,ownerAuditSha,ownerAuditAt,now=Date.now()}={}){
 if(repository?.private!==false||repository?.visibility!=='public'||repository.default_branch!=='main'||repository.archived!==false||repository.disabled!==false||repository.fork!==false)throw new Error('public_dedicated_repository_required');
 const review=branch?.required_pull_request_reviews,checks=branch?.required_status_checks;
 if(branch?.enforce_admins?.enabled!==true||!Number.isSafeInteger(review?.required_approving_review_count)||review.required_approving_review_count<1||review.dismiss_stale_reviews!==true||review.require_last_push_approval!==true||checks?.strict!==true||!Array.isArray(checks.contexts)||!checks.contexts.includes(CHECK)||!Array.isArray(checks.checks)||!checks.checks.some(check=>check.context===CHECK&&check.app_id===APP_ID)||branch.allow_force_pushes?.enabled!==false||branch.allow_deletions?.enabled!==false)throw new Error('protected_main_required');
 const bypass=review.bypass_pull_request_allowances;
 if(!bypass||['users','teams','apps'].some(kind=>!Array.isArray(bypass[kind])||bypass[kind].length))throw new Error('review_bypass_denied');
 if(environment?.deployment_branch_policy?.custom_branch_policies!==true||environment.deployment_branch_policy.protected_branches!==false||!Array.isArray(policies?.branch_policies)||policies.branch_policies.length!==1||policies.branch_policies[0].name!=='main'||policies.branch_policies[0].type!=='branch')throw new Error('main_only_environment_required');
 if(!Array.isArray(environment.protection_rules)||environment.protection_rules.some(rule=>rule.type!=='branch_policy')||customRules?.total_count!==0||!Array.isArray(customRules.custom_deployment_protection_rules)||customRules.custom_deployment_protection_rules.length)throw new Error('unexpected_manual_or_custom_environment_rule');
 const at=Date.parse(ownerAuditAt);
 if(!/^[a-f0-9]{40}$/.test(sourceSha??'')||ownerAuditSha!==sourceSha||!Number.isFinite(at)||at>now+300000||now-at>30*86400000)throw new Error('fresh_exact_source_owner_audit_required');
 // An absent REST can_admins_bypass field is UNKNOWN. Owner UI review is separate,
 // never represented as machine verification. Rulesets cannot weaken this classic baseline.
 if(environment.can_admins_bypass===true)throw new Error('environment_admin_bypass_denied');
 return {machineBaselineVerified:true,ownerAuditRecorded:true,hiddenSettingsMachineVerified:false};
}
async function json(response){if(!response.ok||!response.body||response.headers.get('link'))throw new Error('protection_unavailable_or_paginated');const chunks=[];let size=0;for await(const chunk of response.body){size+=chunk.length;if(size>1024*1024)throw new Error('protection_response_invalid');chunks.push(chunk);}return JSON.parse(Buffer.concat(chunks).toString('utf8'));}
export async function verifyProtection({repository,sourceSha,token,ownerAuditSha,ownerAuditAt,fetcher=fetch,now=Date.now()}){
 if(!/^[A-Za-z0-9_-]+\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(repository??'')||repository.includes('..')||typeof token!=='string'||token.length<20||!/^[a-f0-9]{40}$/.test(sourceSha??''))throw new Error('dedicated_metadata_token_and_context_required');
 const read=async(path,authenticated=false)=>json(await fetcher(`https://api.github.com/repos/${repository}${path}`,{headers:{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',...(authenticated?{Authorization:`Bearer ${token}`}:{})},redirect:'error',signal:AbortSignal.timeout(10000)}));
 const [repo,branch,current,environment,policies,customRules]=await Promise.all([read(''),read('/branches/main/protection',true),read('/branches/main'),read('/environments/security-backup'),read('/environments/security-backup/deployment-branch-policies?per_page=100'),read('/environments/security-backup/deployment_protection_rules')]);
 if(repo.full_name?.toLowerCase()!==repository.toLowerCase()||current.name!=='main'||current.commit?.sha!==sourceSha)throw new Error('reviewed_main_source_moved');
 return assertTrustedAutomation(branch,environment,policies,{repository:repo,customRules,sourceSha,ownerAuditSha,ownerAuditAt,now});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{if(process.env.GITHUB_REF!=='refs/heads/main')throw new Error();await verifyProtection({repository:process.env.GITHUB_REPOSITORY,sourceSha:process.env.GITHUB_SHA,token:process.env.GH_PROTECTION_METADATA_TOKEN,ownerAuditSha:process.env.RECOVERY_POLICY_REVIEWED_SHA,ownerAuditAt:process.env.RECOVERY_POLICY_REVIEWED_AT});console.log('Public runner machine policy inspected; exact-source owner audit recorded. Hosted backup readiness remains separate.');}catch{console.error('Unattended recovery blocked: require dedicated read-only metadata audit, reviewed protected main, main-only environment and fresh owner settings review. No credentials or provider configuration are printed.');process.exitCode=1;}}
