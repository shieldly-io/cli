#!/usr/bin/env node
var ne=Object.create;var G=Object.defineProperty;var re=Object.getOwnPropertyDescriptor;var ie=Object.getOwnPropertyNames;var le=Object.getPrototypeOf,ae=Object.prototype.hasOwnProperty;var ce=(e,s,o,n)=>{if(s&&typeof s=="object"||typeof s=="function")for(let t of ie(s))!ae.call(e,t)&&t!==o&&G(e,t,{get:()=>s[t],enumerable:!(n=re(s,t))||n.enumerable});return e};var W=(e,s,o)=>(o=e!=null?ne(le(e)):{},ce(s||!e||!e.__esModule?G(o,"default",{value:e,enumerable:!0}):o,e));var k=require("node:fs"),Y=require("node:path");var $=require("node:fs"),J=require("node:os"),z=require("node:path"),O="Shieldly-CLI/1.0.4",U=(0,z.join)((0,J.homedir)(),".shieldly","config.json"),pe="https://api.shieldly.io",ye="https://www.shieldly.io",H=5;function K(){try{return JSON.parse((0,$.readFileSync)(U,"utf8"))}catch{return{}}}function de(e){try{(0,$.mkdirSync)((0,z.dirname)(U),{recursive:!0}),(0,$.writeFileSync)(U,`${JSON.stringify(e,null,2)}
`)}catch{}}function S(e){return e||(process.env.SHIELDLY_API_KEY?process.env.SHIELDLY_API_KEY:K().apiKey||null)}function q(){let e=K().demoCount;return typeof e=="number"&&e>0?e:0}function _(){return q()>=H}function j(){let e=K();return e.demoCount=q()+1,de(e),Math.max(0,H-e.demoCount)}function D(){return`You've used all ${H} free demo analyses.

  Get an API key (Builder plan or above) for higher limits: https://www.shieldly.io/app/api

Then set SHIELDLY_API_KEY or pass --api-key.`}function N(){return(process.env.SHIELDLY_API_URL||pe).replace(/\/$/,"")}function me(){return(process.env.SHIELDLY_WEB_URL||ye).replace(/\/$/,"")}async function P(e,s){let o=me(),n=await fetch(`${o}${e}`,{method:"POST",headers:{"Content-Type":"application/json","User-Agent":O},body:JSON.stringify(s)});if(n.status===429)throw new Error("Demo rate limit reached. Get an API key (Builder plan or above) for higher limits: https://www.shieldly.io/app/api");if(!n.ok){let t=await n.json().catch(()=>({}));throw new Error(t.error||`API error ${n.status}`)}return n.json()}async function A(e,s,o){let n=N(),t=await fetch(`${n}${e}`,{method:"POST",headers:{"Content-Type":"application/json","User-Agent":O,Authorization:`Bearer ${o}`},body:JSON.stringify(s)});if(t.status===202){let i=await t.json().catch(()=>({}));if(i.jobId)return ue(i.jobId,o);throw new Error("Analysis queued but no job ID returned \u2014 try again")}if(!t.ok){let i=await t.json().catch(()=>({}));throw new Error(i.error||`API error ${t.status}`)}return t.json()}async function ue(e,s){let o=[2e3,3e3,5e3],n=Date.now(),t=0;for(let i=0;i<180;i++){let l=o[Math.min(i,o.length-1)];await new Promise(r=>setTimeout(r,l));let y=Math.round((Date.now()-n)/1e3);process.stderr.write(`\rAI-Powered analysis in progress\u2026 (${y}s)`);let a;try{a=await T(`/v1/jobs/${encodeURIComponent(e)}`,s),t=0}catch(r){if(++t>=3)throw process.stderr.write(`
`),r;continue}if(a.status==="complete")return process.stderr.write(`
`),{...a.result,unitInfo:a.unitInfo};if(a.status==="failed")throw process.stderr.write(`
`),new Error(a.error||"Analysis failed")}throw process.stderr.write(`
`),new Error("Analysis timed out after polling")}async function T(e,s){let o=N(),n=await fetch(`${o}${e}`,{headers:{Authorization:`Bearer ${s}`,"User-Agent":O}});if(!n.ok){let t=await n.json().catch(()=>({}));throw new Error(t.error||`API error ${n.status}`)}return n.json()}async function V(e,s,o){let n=N(),t=await fetch(`${n}${e}`,{method:"DELETE",headers:{"Content-Type":"application/json","User-Agent":O,Authorization:`Bearer ${o}`},body:JSON.stringify(s)});if(!t.ok){let i=await t.json().catch(()=>({}));throw new Error(i.error||`API error ${t.status}`)}return t.json()}function R(e){return(0,$.existsSync)(e)||(console.error(`Error: File not found: ${e}`),process.exit(1)),(0,$.statSync)(e).isDirectory()&&(console.error(`Error: ${e} is a directory, not a file.
  For a CDK output directory, use: shieldly analyze-cf ${e}`),process.exit(1)),(0,$.readFileSync)(e,"utf8")}var F={CRITICAL:"\x1B[31m",HIGH:"\x1B[33m",MEDIUM:"\x1B[36m",LOW:"\x1B[32m",INFO:"\x1B[90m"},d="\x1B[0m",E="\x1B[1m",w="\x1B[2m",B="\x1B[36m";function v(e,s){if(s==="json"){console.log(JSON.stringify(e,null,2));return}let{score:o,riskLevel:n,findings:t=[],cached:i,summary:l,positives:y=[],unitInfo:a}=e,r=o==null?"\u2014":`${o}/100`;if(console.log(""),console.log(`${E}AI-Powered Security Analysis \u2014 Shieldly${d}`),console.log(`${w}${"\u2500".repeat(50)}${d}`),console.log(`  ${E}Security Score:${d}  ${fe(o)}${r}${d}`),console.log(`  ${E}Risk Level:${d}  ${he(n)}${n||"Unknown"}${d}`),i&&console.log(`  ${w}(cached result)${d}`),l&&(console.log(""),console.log(`  ${w}${l}${d}`)),console.log(""),y.length>0){console.log(`${E}What's good:${d}`);for(let c of y)console.log(`  ${F.LOW}[+]${d} ${w}${c}${d}`);console.log("")}if(t.length===0)console.log(`  ${B}[PASS] No findings${d}`);else{console.log(`${E}Findings (${t.length}):${d}`);for(let c of t){let u=F[(c.severity||"").toUpperCase()]||"";console.log(`
  ${u}[${c.severity}]${d} ${E}${c.title}${d}`),c.resource&&c.resource!=="*"&&console.log(`         ${w}Resource: ${c.resource}${d}`),c.description&&console.log(`         ${w}${c.description}${d}`),c.remediation&&console.log(`  ${B}Fix:${d}  ${c.remediation}`)}}a&&typeof a.unitsUsed=="number"&&typeof a.cap=="number"&&(console.log(""),console.log(`  ${w}Units used: ${a.unitsUsed}/${a.cap}${d}`)),e.demoInfo&&typeof e.demoInfo.analysesRemaining=="number"&&(console.log(""),console.log(`  ${w}Demo analyses remaining: ${e.demoInfo.analysesRemaining}. Get an API key (Builder plan or above) for more: https://www.shieldly.io/app/api${d}`)),console.log("")}function fe(e){return e==null?"":e>=80?"\x1B[32m":e>=50?"\x1B[33m":"\x1B[31m"}function he(e){let s=(e||"").toUpperCase();return F[s]||""}var $e=`
Usage: shieldly analyze-cf <template-file-or-dir> [options]

Analyze a CloudFormation template (or directory of templates) for security issues using AI.

Arguments:
  template-file-or-dir  Path to a JSON CF template, or a directory (e.g. cdk.out/)
                        containing synthesized stacks. All *.template.json files are
                        analyzed automatically.

Options:
  --format <fmt>    Output format: table | json  (default: table)
  --api-key <key>   API key (or set SHIELDLY_API_KEY env var)
  -h, --help        Show this help

Authentication:
  No key needed for demo mode (rate-limited). Set SHIELDLY_API_KEY for full access.
  Get an API key (Builder plan or above): https://www.shieldly.io/app/api

Examples:
  shieldly analyze-cf template.json
  shieldly analyze-cf cdk.out/
  shieldly analyze-cf cdk.out/ --format json

CDK integration (add to package.json scripts):
  "synth:check": "cdk synth && shieldly analyze-cf cdk.out/"

cdk.json hook (runs after every cdk synth):
  {
    "hooks": {
      "afterSynth": ["sh", "-c", "shieldly analyze-cf cdk.out/ || true"]
    }
  }
`;function ge(e){try{let s=(0,k.readFileSync)((0,Y.join)(e,"manifest.json"),"utf8"),o=JSON.parse(s);if(!o.artifacts||typeof o.artifacts!="object")return null;let n=Object.values(o.artifacts).filter(t=>t.type==="aws:cloudformation:stack"&&t.properties?.templateFile).map(t=>(0,Y.join)(e,t.properties.templateFile)).filter(t=>(0,k.existsSync)(t));return n.length>0?n:null}catch{return null}}function Ie(e){let s=ge(e);if(s)return s;let o=[],n;try{n=(0,k.readdirSync)(e,{withFileTypes:!0})}catch{return o}for(let t of n){if(!t.isFile())continue;let i=t.name;(i.endsWith(".template.json")||i.endsWith(".template.yaml"))&&o.push((0,Y.join)(e,i))}return o}async function ke(e,s,o,n,t){let i=(0,k.readFileSync)(e,"utf8");o!=="json"&&t>1?process.stdout.write(`[${n}/${t}] Analyzing ${e}\u2026
`):o!=="json"&&process.stdout.write(`Analyzing ${e}\u2026
`);let l=s?await A("/v1/analyze/cf",{template:i},s):await P("/api/demo/analyze-iam",{template:i,policyType:"cf"});return!s&&!l.cached&&j(),{filePath:e,data:l}}async function Z(e){if(e.includes("-h")||e.includes("--help")||e.length===0){console.log($e);return}let s=e.indexOf("--format"),o=s!==-1?e[s+1]:"table";s!==-1&&!["table","json"].includes(o)&&(console.error(`Error: invalid --format "${o}". Use: table | json`),process.exit(1));let n=e.indexOf("--api-key"),t=S(n!==-1?e[n+1]:null),i=new Set;for(let r of[s,n])r!==-1&&(i.add(r),i.add(r+1));let l=e.find((r,c)=>!i.has(c)&&!r.startsWith("--"));l||(console.error("Error: template-file-or-dir argument is required"),process.exit(1)),!t&&_()&&(console.error(D()),process.exit(1)),!t&&o!=="json"&&console.log("Demo mode (rate-limited, no signup required). Get an API key (Builder plan or above) for higher limits: https://www.shieldly.io/app/api");let y=(0,k.statSync)(l,{throwIfNoEntry:!1});if(y||(console.error(`Error: path not found: ${l}`),process.exit(1)),y.isDirectory()){let r=Ie(l);r.length===0&&(console.error(`Error: no CloudFormation templates (*.template.json / *.template.yaml) found in ${l}
Run "cdk synth" first to generate stack templates.`),process.exit(1)),o!=="json"&&console.log(`Found ${r.length} stack template(s) in ${l}
`);let c=[],u=0,p=0;for(let f=0;f<r.length;f++){if(!t&&_()){o!=="json"&&console.error(`
Demo allowance reached \u2014 remaining stacks skipped. Get an API key (Builder plan or above): https://www.shieldly.io/app/api`);break}try{let{filePath:g,data:I}=await ke(r[f],t,o,f+1,r.length);c.push({filePath:g,data:I}),u+=(I.findings||[]).filter(M=>M.severity?.toUpperCase()==="CRITICAL").length,p+=(I.findings||[]).filter(M=>M.severity?.toUpperCase()==="HIGH").length,o!=="json"&&v(I,o)}catch(g){if(console.error(`Error analyzing ${r[f]}: ${g.message}`),!t&&/rate limit/i.test(g.message))break}}if(o==="json")console.log(JSON.stringify(c.map(({filePath:f,data:g})=>({stack:f,...g})),null,2));else if(r.length>1){let f=c.reduce((g,I)=>g+(I.data.findings||[]).length,0);console.log(`
Summary: ${r.length} stacks \xB7 ${f} total findings \xB7 ${u} critical \xB7 ${p} high`)}(u>0||p>0)&&process.exit(1);return}let a=R(l);o!=="json"&&console.log(`Analyzing ${l}\u2026`);try{let r=t?await A("/v1/analyze/cf",{template:a},t):await P("/api/demo/analyze-iam",{template:a,policyType:"cf"});v(r,o);let c=(r.findings||[]).filter(p=>p.severity?.toUpperCase()==="CRITICAL").length,u=(r.findings||[]).filter(p=>p.severity?.toUpperCase()==="HIGH").length;(c>0||u>0)&&process.exit(1)}catch(r){console.error(`Error: ${r.message}`),process.exit(1)}}var we=`
Usage: shieldly analyze-iam <policy-file> [options]

Analyze an AWS IAM policy for security issues using AI.

Arguments:
  policy-file       Path to a JSON file containing the IAM policy

Options:
  --type <type>     identity (default) | cross_account
                    Any IAM or resource policy JSON works as 'identity'.
                    'cross_account' expects {"identityPolicy":\u2026,"trustPolicy":\u2026}.
  --format <fmt>    Output format: table | json  (default: table)
  --api-key <key>   API key (or set SHIELDLY_API_KEY env var)
  -h, --help        Show this help

Examples:
  shieldly analyze-iam policy.json
  shieldly analyze-iam policy.json --type cross_account --format json
  SHIELDLY_API_KEY=sk_... shieldly analyze-iam policy.json
`;async function Q(e){if(e.includes("-h")||e.includes("--help")||e.length===0){console.log(we);return}let s=e.indexOf("--type"),o=s!==-1?e[s+1]:"identity",n=e.indexOf("--format"),t=n!==-1?e[n+1]:"table";s!==-1&&!["identity","iam_identity","cross_account"].includes(o)&&(console.error(`Error: invalid --type "${o}". Use: identity | cross_account`),process.exit(1)),n!==-1&&!["table","json"].includes(t)&&(console.error(`Error: invalid --format "${t}". Use: table | json`),process.exit(1));let i=e.indexOf("--api-key"),l=S(i!==-1?e[i+1]:null);!l&&_()&&(console.error(D()),process.exit(1));let y=new Set;for(let p of[s,n,i])p!==-1&&(y.add(p),y.add(p+1));let a=e.find((p,f)=>!y.has(f)&&!p.startsWith("--"));a||(console.error("Error: policy-file argument is required"),process.exit(1));let r=R(a);try{JSON.parse(r)}catch{console.error("Error: policy-file must be valid JSON"),process.exit(1)}let c=r.trim(),u=o==="identity"||o==="iam_identity"?"iam_identity":o==="cross_account"?"cross_account":"iam_identity";t!=="json"&&(console.log(`Analyzing ${a} (type: ${u})\u2026`),l||console.log("Demo mode (rate-limited, no signup required). Get an API key (Builder plan or above) for higher limits: https://www.shieldly.io/app/api"));try{let p=l?await A("/v1/analyze/iam",{policy:c,policyType:u},l):await P("/api/demo/analyze-iam",{policy:c,policyType:u});!l&&!p.cached&&j(),v(p,t);let f=(p.findings||[]).filter(I=>I.severity?.toUpperCase()==="CRITICAL").length,g=(p.findings||[]).filter(I=>I.severity?.toUpperCase()==="HIGH").length;(f>0||g>0)&&process.exit(1)}catch(p){console.error(`Error: ${p.message}`),process.exit(1)}}var X=`
Usage: shieldly api-keys <subcommand> [options]

Manage Shieldly API keys.

Subcommands:
  list                        List all your API keys
  create --label <label>      Create a new API key
         --scopes <scopes>    Comma-separated scopes: iam,cf,cost (default: iam,cf)
  revoke <key-id>             Revoke an API key by ID

Options:
  --api-key <key>   API key (or set SHIELDLY_API_KEY env var)
  --format json     Output as JSON
  -h, --help        Show this help

Examples:
  shieldly api-keys list
  shieldly api-keys create --label "CI/CD Key" --scopes iam,cf
  shieldly api-keys revoke key_abc123
`,b="\x1B[1m",ee="\x1B[2m",oe="\x1B[36m",h="\x1B[0m";function be(e){return e?new Date(e).toLocaleDateString("en-US",{month:"short",day:"numeric",year:"numeric"}):"\u2014"}async function te(e){if(e.includes("-h")||e.includes("--help")||e.length===0){console.log(X);return}let s=e[0],o=e.slice(1),n=o.indexOf("--api-key"),t=S(n!==-1?o[n+1]:null),i=o.indexOf("--format"),l=i!==-1?o[i+1]:"table";if(i!==-1&&!["table","json"].includes(l)&&(console.error(`Error: invalid --format "${l}". Use: table | json`),process.exit(1)),t||(console.error(`API key management requires an API key to authenticate.

  Get an API key (Builder plan or above): https://www.shieldly.io/app/api

Set SHIELDLY_API_KEY or use --api-key once you have your key.`),process.exit(1)),s==="list"){try{let a=(await T("/v1/api-keys",t)).keys||[];if(l==="json"){console.log(JSON.stringify(a,null,2));return}if(a.length===0){console.log("No API keys found. Create one at https://www.shieldly.io/app/api");return}console.log(""),console.log(`${b}API Keys (${a.length}):${h}`),console.log(`${ee}${"\u2500".repeat(60)}${h}`);for(let r of a){let c=(r.scopes||[]).join(", ")||"all";console.log(`  ${oe}${r.keyId}${h}`),console.log(`    ${b}Label:${h}  ${r.label||"(unlabeled)"}`),console.log(`    ${b}Scopes:${h} ${c}`),console.log(`    ${b}Uses:${h}   ${r.usageCount||0}`),console.log(`    ${b}Created:${h} ${be(r.createdAt)}`),console.log("")}}catch(y){console.error(`Error: ${y.message}`),process.exit(1)}return}if(s==="create"){let y=o.indexOf("--label"),a=y!==-1?o[y+1]:"CLI Key",r=o.indexOf("--scopes"),u=(r!==-1?o[r+1]:"iam,cf").split(",").map(p=>p.trim()).filter(Boolean);try{let p=await A("/v1/api-keys",{label:a,scopes:u},t);if(l==="json"){console.log(JSON.stringify(p,null,2));return}console.log(""),console.log(`${b}[OK] API key created${h}`),console.log(`  ${b}Key ID:${h} ${p.keyId}`),console.log(`  ${b}API Key:${h} ${oe}${p.apiKey}${h}`),console.log(`  ${ee}Store this key securely \u2014 it won't be shown again.${h}`),console.log("")}catch(p){console.error(`Error: ${p.message}`),process.exit(1)}return}if(s==="revoke"){let y=new Set;n!==-1&&(y.add(n),y.add(n+1)),i!==-1&&(y.add(i),y.add(i+1));let a=o.find((r,c)=>!y.has(c)&&!r.startsWith("--"));a||(console.error(`Error: key-id argument is required
  Usage: shieldly api-keys revoke <key-id>`),process.exit(1));try{if(await V("/v1/api-keys",{keyId:a},t),l==="json"){console.log(JSON.stringify({success:!0,keyId:a}));return}console.log(`[OK] API key ${a} revoked`)}catch(r){console.error(`Error: ${r.message}`),process.exit(1)}return}console.error(`Unknown subcommand: ${s}`),console.log(X),process.exit(1)}var Ae=`
_shieldly() {
  local cur prev words cword
  _init_completion || return

  local commands="analyze-iam analyze-cf api-keys completion"
  local global_opts="--api-key --help -h --version -v"

  case $prev in
    analyze-iam)
      if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "--type --format --api-key --help -h" -- "$cur"))
      else
        COMPREPLY=($(compgen -f -- "$cur"))
      fi
      return
      ;;
    analyze-cf)
      if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "--format --api-key --help -h" -- "$cur"))
      else
        COMPREPLY=($(compgen -f -- "$cur"))
      fi
      return
      ;;
    api-keys)
      COMPREPLY=($(compgen -W "list create revoke" -- "$cur"))
      return
      ;;
    completion)
      COMPREPLY=($(compgen -W "bash zsh install" -- "$cur"))
      return
      ;;
    --type)
      COMPREPLY=($(compgen -W "identity cross_account" -- "$cur"))
      return
      ;;
    --format)
      COMPREPLY=($(compgen -W "table json" -- "$cur"))
      return
      ;;
    --label)
      return
      ;;
    --scopes)
      COMPREPLY=($(compgen -W "iam cf cost" -- "$cur"))
      return
      ;;
    --api-key)
      return
      ;;
  esac

  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "$global_opts" -- "$cur"))
  elif [[ $cword -eq 1 ]]; then
    COMPREPLY=($(compgen -W "$commands" -- "$cur"))
  fi
} &&
  complete -F _shieldly shieldly
`,xe=`
#compdef shieldly

_shieldly() {
  local -a opts
  local curcontext="$curcontext" state line ret=1

  _arguments -C     '(-h --help)'{-h,--help}'[Show help]'     '(-v --version)'{-v,--version}'[Show version]'     '--api-key[API key]:api key'     '1: :->command'     '*: :->args'     && ret=0

  case $state in
    command)
      local commands; commands=(
        'analyze-iam:Analyze an IAM policy for security issues'
        'analyze-cf:Analyze a CloudFormation template'
        'api-keys:Manage API keys'
        'completion:Generate shell completion script'
      )
      _describe 'command' commands && ret=0
      ;;
    args)
      case $words[1] in
        analyze-iam)
          _arguments             '--type[Policy type]:type:(identity cross_account)'             '--format[Output format]:format:(table json)'             '--api-key[API key]:api key'             '(-h --help)'{-h,--help}'[Show help]'             '*:policy file:_files'             && ret=0
          ;;
        analyze-cf)
          _arguments             '--format[Output format]:format:(table json)'             '--api-key[API key]:api key'             '(-h --help)'{-h,--help}'[Show help]'             '*:template file:_files'             && ret=0
          ;;
        api-keys)
          _arguments             '--format[Output format]:format:(table json)'             '--api-key[API key]:api key'             '1: :->subcommand'             '*: :->args'             && ret=0
          case $state in
            subcommand)
              local subcommands; subcommands=(
                'list:List all API keys'
                'create:Create a new API key'
                'revoke:Revoke an API key'
              )
              _describe 'subcommand' subcommands && ret=0
              ;;
            args)
              case $words[2] in
                create)
                  _arguments                     '--label[Key label]'                     '--scopes[Comma-separated scopes]:scopes:(iam cf cost)'                     && ret=0
                  ;;
                revoke)
                  _arguments '*:key id' && ret=0
                  ;;
              esac
              ;;
          esac
          ;;
        completion)
          _arguments             '1: :->shell'             && ret=0
          case $state in
            shell)
              local shells; shells=(
                'bash:Generate bash completion'
                'zsh:Generate zsh completion'
                'install:Install completion for current shell'
              )
              _describe 'shell' shells && ret=0
              ;;
          esac
          ;;
      esac
      ;;
  esac

  return ret
}

_shieldly
`,Ee=`
Usage: shieldly completion <shell>

Generate shell completion scripts for the shieldly CLI.

Shells:
  bash       Generate bash completion
  zsh        Generate zsh completion
  install    Auto-detect shell and install completion

Examples:
  eval "$(shieldly completion bash)"       # Source bash completion
  shieldly completion zsh > /usr/local/share/zsh/site-functions/_shieldly  # Install zsh completion
  shieldly completion install                # Auto-detect and install
`;async function se(e){if(!e.length||e.includes("-h")||e.includes("--help")){console.log(Ee);return}let s=e[0];switch(s){case"bash":console.log(Ae.trimStart());break;case"zsh":console.log(xe.trimStart());break;case"install":await Se();break;default:console.error(`Unsupported shell: ${s}`),console.log("Supported shells: bash, zsh"),process.exit(1)}}async function Se(){let e=process.env.SHELL||"",s=process.env.HOME||"";if(e.includes("zsh")){let o=`${s}/.zshrc`,n=`
# shieldly CLI completion
autoload -Uz compinit && compinit -C 2>/dev/null
eval "$(shieldly completion zsh)" 2>/dev/null`;try{let{readFileSync:t,appendFileSync:i,existsSync:l}=await import("node:fs");if(l(o)&&t(o,"utf8").includes("shieldly completion")){console.log("shieldly completion already installed in ~/.zshrc");return}i(o,n),console.log("Installed shieldly completion in ~/.zshrc"),console.log("Run: source ~/.zshrc")}catch(t){console.error(`Failed to install: ${t.message}`),process.exit(1)}}else if(e.includes("bash")){let o=`${s}/.bashrc`,n=`
# shieldly CLI completion
source /dev/stdin <<< "$(shieldly completion bash)" 2>/dev/null`;try{let{readFileSync:t,appendFileSync:i,existsSync:l}=await import("node:fs");if(l(o)&&t(o,"utf8").includes("shieldly completion")){console.log("shieldly completion already installed in ~/.bashrc");return}i(o,n),console.log("Installed shieldly completion in ~/.bashrc"),console.log("Run: source ~/.bashrc")}catch(t){console.error(`Failed to install: ${t.message}`),process.exit(1)}}else console.error(`Unsupported shell: ${e}. Install manually:`),console.log('  eval "$(shieldly completion bash)"  # For bash'),console.log('  eval "$(shieldly completion zsh)"   # For zsh'),process.exit(1)}var x="\x1B[1m",C="\x1B[36m",L="\x1B[2m",m="\x1B[0m",_e="1.0.4",Pe=`
${x}shieldly${m} \u2014 AI-Powered Security Analysis for AWS

${x}Usage:${m}
  shieldly <command> [args] [options]

${x}Commands:${m}
  ${C}analyze-iam${m}  <policy-file>          Analyze an IAM policy for security issues
  ${C}analyze-cf${m}   <template-file-or-dir> Analyze a CloudFormation template or CDK output directory
  ${C}api-keys${m}     list|create|revoke     Manage API keys
  ${C}completion${m}   bash|zsh|install       Generate shell completion

${x}Global Options:${m}
  --api-key <key>   API key (or set SHIELDLY_API_KEY env var)
  --version         Show version
  -h, --help        Show this help

${x}Authentication:${m}
  Set your API key via env var:   export SHIELDLY_API_KEY=sk_...
  Get an API key (Builder plan or above) at: ${C}https://www.shieldly.io/app/api${m}

${x}Examples:${m}
  ${L}# Analyze an IAM policy or CF template (no API key needed \u2014 demo mode)${m}
  shieldly analyze-iam policy.json

  ${L}# Analyze a single CloudFormation template${m}
  shieldly analyze-cf template.json

  ${L}# Scan all CDK stacks after synthesis (reads manifest.json \u2014 current stacks only)${m}
  cdk synth && shieldly analyze-cf cdk.out/

  ${L}# List API keys${m}
  shieldly api-keys list

  ${L}# Use in CI${m}
  SHIELDLY_API_KEY=\${{ secrets.SHIELDLY_API_KEY }} shieldly analyze-iam policy.json
`;async function ve(){let[,,e,...s]=process.argv;switch((!e||e==="-h"||e==="--help")&&(console.log(Pe),process.exit(0)),(e==="--version"||e==="-v")&&(console.log(_e),process.exit(0)),e){case"analyze-iam":await Q(s);break;case"analyze-cf":await Z(s);break;case"api-keys":await te(s);break;case"completion":await se(s);break;default:console.error(`Unknown command: ${e}`),console.log(`Run ${x}shieldly --help${m} for usage`),process.exit(1)}}ve().catch(e=>{console.error("Fatal error:",e.message),process.exit(1)});
