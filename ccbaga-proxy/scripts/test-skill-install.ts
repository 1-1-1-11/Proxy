/**
 * [INPUT]: 完整公开 Skill 目录、Agent Skills YAML 规范与 npm skills 1.7.2。
 * [OUTPUT]: 四个 agent 的真实全局复制安装、文件完整性和无符号链接验证。
 * [POS]: 隔离安装回归；临时用户目录/缓存，禁统计和凭据环境，不运行网络部署。
 * [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
 */
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,readFileSync,copyFileSync,rmSync,lstatSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,join,dirname} from 'node:path';
import {parse} from 'yaml';
const root=resolve(import.meta.dir,'..');
const skill=join(root,'skills/ccbaga-network');
const text=readFileSync(join(skill,'SKILL.md'),'utf8');
const metadata=parse(text.split(/^---\s*$/m)[1]);
assert.equal(metadata.name,'ccbaga-network');
assert.match(metadata.name,/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
assert(metadata.name.length<=64 && metadata.description.length>0 && metadata.description.length<=1024);
assert.equal(metadata.license,'MIT');
assert(metadata.compatibility.length<=500);
assert(Object.values(metadata.metadata).every(value=>typeof value==='string'));
assert(text.split('\n').length<500);
const temporary=mkdtempSync(join(tmpdir(),'ccbaga-npm-install-'));
try {
    const source=join(temporary,'技能 with spaces/ccbaga-network');
    const tracked=spawnSync('git',['ls-files','--cached','--others','--exclude-standard','--','skills/ccbaga-network'],{cwd:root,encoding:'utf8'});
    assert.equal(tracked.status,0);
    const files=[...new Set(tracked.stdout.trim().split('\n'))].map(path=>path.slice('skills/ccbaga-network/'.length));
    for(const name of files){const destination=join(source,name);mkdirSync(dirname(destination),{recursive:true});copyFileSync(join(skill,name),destination);}
    const cache=join(temporary,'npm-cache');
    const base=Object.fromEntries(Object.entries(process.env).filter(([name])=>!name.startsWith('APPLE_')&&!name.startsWith('TAURI_SIGNING_PRIVATE_KEY')&&!['GH_TOKEN','GITHUB_TOKEN','NPM_TOKEN','NODE_AUTH_TOKEN'].includes(name)));
    for(const agent of ['codex','cursor','opencode','github-copilot']) {
        const home=join(temporary,agent);mkdirSync(home);
        const env={...base,HOME:home,USERPROFILE:home,XDG_CONFIG_HOME:join(home,'.config'),npm_config_cache:cache,DO_NOT_TRACK:'1',DISABLE_TELEMETRY:'1',CC_SKILL_SOURCE:source};
        const args=['--yes','skills@1.7.2','add',source,'--skill','ccbaga-network','--global','--agent',agent,'--copy','--yes'];
        const result=process.platform==='win32' ? spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',`& npx.cmd --yes skills@1.7.2 add $env:CC_SKILL_SOURCE --skill ccbaga-network --global --agent ${agent} --copy --yes; exit $LASTEXITCODE`],{env,cwd:temporary,encoding:'utf8',timeout:180_000}) : spawnSync('npx',args,{env,cwd:temporary,encoding:'utf8',timeout:180_000});
        assert.equal(result.status,0,result.stderr||result.stdout||String(result.error));
        const installed=join(home,'.agents/skills/ccbaga-network');
        assert(!lstatSync(installed).isSymbolicLink());
        for(const name of files){assert(!lstatSync(join(installed,name)).isSymbolicLink());assert.deepEqual(readFileSync(join(installed,name)),readFileSync(join(source,name)));}
        console.info(`npm Skill installation verified: ${agent}, all ${files.length} public files preserved.`);
    }
} finally {rmSync(temporary,{recursive:true,force:true});}
