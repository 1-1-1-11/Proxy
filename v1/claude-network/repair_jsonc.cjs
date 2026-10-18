// Microsoft jsonc-parser 3.3.1 is bundled locally with its MIT license.
const fs = require('fs');
const jsonc = require('./vendor/jsonc-parser/lib/main.js');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
let text = input.text;
const errors = [];
const data = jsonc.parse(text, errors, {allowTrailingComma: true});
if (errors.length || !data || typeof data !== 'object' || Array.isArray(data)) {
  process.stdout.write(JSON.stringify({ok:false, error:'Invalid settings JSON; file preserved'}));
  process.exit(0);
}
const wanted = input.values;
const edits = [];
if (input.kind === 'claude') {
  // User configuration is authoritative; existing project overrides are repaired only if present.
  for (const [name,value] of Object.entries(wanted)) {
    if (input.always || Object.keys(data.env || {}).some(k => k.toUpperCase() === name.toUpperCase())) {
      if (data.env?.[name] !== value) edits.push([['env',name],value]);
    }
  }
} else {
  const list = data['claudeCode.environmentVariables'];
  if (list !== undefined && !Array.isArray(list)) {
    process.stdout.write(JSON.stringify({ok:false,error:'Invalid extension environment list; file preserved'}));
    process.exit(0);
  }
  for (const [i,item] of (list || []).entries()) {
    const key = String(item.name || '').toUpperCase();
    if (Object.hasOwn(wanted,key) && item.value !== wanted[key])
      edits.push([['claudeCode.environmentVariables',i,'value'],wanted[key]]);
  }
  if (input.always) {
    const merged=(list || []).map(item => ({...item,value: wanted[String(item.name || '').toUpperCase()] ?? item.value}));
    for (const [name,value] of Object.entries(wanted))
      if (!merged.some(item => item.name === name)) merged.push({name,value});
    // A single array edit avoids overlapping edits and preserves unrelated variables.
    edits.length=0;
    if (JSON.stringify(merged)!==JSON.stringify(list)) edits.push([['claudeCode.environmentVariables'],merged]);
  }
  if ((input.always || data['workbench.externalBrowser'] !== undefined) && data['workbench.externalBrowser'] !== wanted.BROWSER)
    edits.push([['workbench.externalBrowser'],wanted.BROWSER]);
}
for (const [path,value] of edits) text = jsonc.applyEdits(text,jsonc.modify(text,path,value,{formattingOptions:{insertSpaces:true,tabSize:2,eol:text.includes('\r\n')?'\r\n':'\n'}}));
process.stdout.write(JSON.stringify({ok:true,text,changes:edits.length}));
