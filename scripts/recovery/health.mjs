import { pathToFileURL } from "node:url";
import { RecoveryGateway } from "./backup.mjs";
/** State only: runtime timestamps/ages never belong in public Actions logs. */
export function recoveryHealth(latest, now=Date.now()) {
 const finished=Date.parse(latest?.finished_at),age=now-finished;
 if(latest?.state!=="sealed"||!Number.isFinite(age)||age<0||age>=24*3600000)return "critical";
 return age>=18*3600000?"warning":"healthy";
}
export async function main(raw=process.env) {
 const origin=new URL(raw.RECOVERY_APP_ORIGIN||"");
 if(origin.protocol!=="https:"||origin.pathname!=="/"||origin.username||origin.password||origin.search||origin.hash||typeof raw.RECOVERY_RUNNER_SECRET!=="string"||raw.RECOVERY_RUNNER_SECRET.length<32)throw new Error("canonical health configuration required");
 const latest=await new RecoveryGateway({origin:origin.origin,secret:raw.RECOVERY_RUNNER_SECRET,sourceProject:raw.RECOVERY_SOURCE_PROJECT_REF}).control("latest");
 return recoveryHealth(latest);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{
 const state=await main();
 if(state==="healthy")console.log("Recovery health check passed; runtime details remain private. Restore drill remains a separate gate.");
 else {console.error(state==="warning"?"::warning title=Recovery early-stale warning::Investigate the protected recovery system. No runtime data is printed.":"::error title=Recovery critical or unavailable::Inspect the protected recovery system. No runtime data is printed.");process.exitCode=1;}
}catch{console.error("::error title=Recovery health unavailable::Inspect protected operator diagnostics. Notification delivery is a separate configured gate.");process.exitCode=1;}}
