// Reads only the API host and override names from Claude / VS Code settings.
// Credential values never leave this process; the output holds names and a hostname.
const fs = require('fs');
const jsonc = require('./vendor/jsonc-parser/lib/main.js');
const OVERRIDES = ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN',
  'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_VERTEX', 'CLAUDE_CODE_USE_FOUNDRY'];
const host = value => { try { return new URL(String(value)).hostname || 'invalid'; } catch { return 'invalid'; } };
const files = JSON.parse(fs.readFileSync(0, 'utf8'));
const result = files.map(file => {
  try {
    const errors = [];
    const data = jsonc.parse(fs.readFileSync(file.path, 'utf8').replace(/^\uFEFF/, ''), errors, {allowTrailingComma: true});
    if (errors.length || !data || typeof data !== 'object' || Array.isArray(data)) return {path: file.path, error: 'invalid'};
    let env = {};
    if (file.kind === 'vscode') {
      const list = data['claudeCode.environmentVariables'];
      for (const item of Array.isArray(list) ? list : []) if (item && typeof item.name === 'string') env[item.name] = item.value;
    } else if (data.env && typeof data.env === 'object' && !Array.isArray(data.env)) {
      env = data.env;
    }
    const names = Object.keys(env).map(name => name.toUpperCase());
    const baseKey = Object.keys(env).find(name => name.toUpperCase() === 'ANTHROPIC_BASE_URL');
    const overrides = OVERRIDES.filter(name => names.includes(name));
    if (file.kind === 'claude' && Object.hasOwn(data, 'apiKeyHelper')) overrides.push('apiKeyHelper');
    return {path: file.path, base_url_host: baseKey === undefined ? null : host(env[baseKey]), overrides};
  } catch {
    return {path: file.path, error: 'unreadable'};
  }
});
process.stdout.write(JSON.stringify(result));
