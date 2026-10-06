// Durable network routing. No credentials in this script.
// Health checks cover the complete fixed-exit chains; no direct fallback.
function main(config) {
  const exitName = "静态IP-链式";
  const chainGroup = "静态出口-自动恢复";
  const daily = "日常网络-自动恢复";
  const available = new Set((config.proxies || []).map(p => p.name));
  const preferred = ["日本JP-HY2", "韩国KR-HY2", "新加坡SG-A", "美国USLA2-A"];
  const fronts = preferred.filter(name => available.has(name));
  const providerName = "固定出口链路";
  const previousPayload = config["proxy-providers"]?.[providerName]?.payload || [];
  const original = (config.proxies || []).find(p => p.name === exitName) || previousPayload.find(p => p.name === exitName);
  const protectedGroups = ["Claude-固定出口", "Google-固定出口", "X-固定出口"];
  const dailyGroup = "OpenAI-日常代理";
  const reserved = ["链式前置-固定", "链式前置-自动", chainGroup, daily, "备用机场-日本",
    ...protectedGroups, dailyGroup, "OpenAI-固定出口"];
  const fallback = (name, proxies) => ({name, type: "fallback", proxies: proxies.length ? proxies : ["REJECT"],
    url: "https://www.gstatic.com/generate_204", interval: 30, timeout: 4000,
    lazy: false, "max-failed-times": 2, "expected-status": 204, "empty-fallback": "REJECT"});
  const chains = [];
  const chainPayload = [];
  config.proxies = (config.proxies || []).filter(p => p.name !== exitName && !p.name.startsWith("静态出口·"));
  if (original) {
    for (const [i, front] of fronts.entries()) {
      const name = i === 0 ? exitName : "静态出口·" + front;
      // Explicitly replace the node instead of mutating an earlier object's alias.
      chainPayload.push({...original, name, udp: false, "dialer-proxy": front});
      chains.push(name);
    }
  } else {
    // Missing supplier credentials fail closed, never keep old direct references.
    config.proxies.push({name: exitName, type: "reject"});
    chains.push(exitName);
  }
  // The GUI chain editor clears dialer-proxy only in top-level proxies.
  // Provider payloads remain independent, and each entire chain has its own health check.
  config["proxy-providers"] = {...(config["proxy-providers"] || {})};
  const fixedFallback = fallback(chainGroup, chains);
  if (chainPayload.length) {
    config["proxy-providers"][providerName] = {type: "inline", payload: chainPayload,
      "health-check": {enable: true, url: "https://www.gstatic.com/generate_204",
        interval: 30, timeout: 4000, lazy: false, "expected-status": 204}};
    delete fixedFallback.proxies;
    fixedFallback.use = [providerName];
  } else {
    delete config["proxy-providers"][providerName];
  }
  config["proxy-groups"] = (config["proxy-groups"] || []).filter(g => !reserved.includes(g.name));
  for (const g of config["proxy-groups"]) {
    const target = ["Gemini", "Twitter", "谷歌服务"].includes(g.name) ? chainGroup :
      ["节点选择", "自动选择", "ChatGPT", "Netflix", "Telegram", "TikTok", "WhatsApp", "Copilot", "Steam"].includes(g.name) ? daily : null;
    if (target) {
      for (const key of Object.keys(g)) if (key !== "name") delete g[key];
      Object.assign(g, {type: "select", proxies: [target, "REJECT"]});
    }
  }
  config["proxy-groups"].unshift(
    fallback(daily, fronts), fixedFallback,
    ...protectedGroups.map(name => ({name, type: "select", proxies: [chainGroup, "REJECT"]})),
    {name: dailyGroup, type: "select", proxies: [daily, "REJECT"]}
  );
  // This listener pins Claude CLI independently of rule/global/direct mode.
  config.listeners = (config.listeners || []).filter(l => l.name !== "claude-fixed-http");
  config.listeners.push({name: "claude-fixed-http", type: "http", listen: "127.0.0.1",
    port: 17892, proxy: "Claude-固定出口", users: []});
  const rules = [
    "PROCESS-NAME,claude.exe,Claude-固定出口",
    "PROCESS-NAME,codex.exe,OpenAI-日常代理",
    "PROCESS-NAME,ChatGPT.exe,OpenAI-日常代理",
    "PROCESS-NAME,Antigravity.exe,Google-固定出口"
  ];
  const domains = {
    "Claude-固定出口": ["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com", "clau.de"],
    "OpenAI-日常代理": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "auth0.com"],
    "Google-固定出口": ["google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "googlesyndication.com"],
    "X-固定出口": ["x.com", "twitter.com", "twimg.com", "t.co"]
  };
  for (const [group, suffixes] of Object.entries(domains)) {
    for (const domain of suffixes) rules.push(`DOMAIN-SUFFIX,${domain},${group}`);
  }
  // Keep general DNS and recovery probes independent of the fixed SOCKS exit.
  rules.push("IP-CIDR,1.1.1.1/32,日常网络-自动恢复,no-resolve", "IP-CIDR,8.8.8.8/32,日常网络-自动恢复,no-resolve");
  const own = new Set(rules);
  config.rules = [...rules, ...(config.rules || []).filter(r => !own.has(r) &&
    !r.endsWith(",OpenAI-固定出口") && !["claude.exe", "codex.exe", "ChatGPT.exe", "Antigravity.exe"].some(p => r.startsWith("PROCESS-NAME," + p + ",")) &&
    !r.startsWith("IP-CIDR,1.1.1.1/32,") && !r.startsWith("IP-CIDR,8.8.8.8/32,") &&
    !["DOMAIN,www.cloudflare.com,静态IP-链式", "DOMAIN,api.ipify.org,静态IP-链式"].includes(r))];
  const oldDNS = config.dns || {};
  const originalNodePolicy = oldDNS["proxy-server-nameserver-policy"] || oldDNS["nameserver-policy"] || {};
  // Bootstrap DNS for airport hostnames must not need that same airport connection.
  const nodePolicy = Object.fromEntries(Object.entries(originalNodePolicy).map(([name, servers]) =>
    [name, (Array.isArray(servers) ? servers : [servers]).map(s => s.includes("#") ? s : s + "#DIRECT")]));
  const direct = "https://223.5.5.5/dns-query#DIRECT";
  const general = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"];
  config.dns = {...oldDNS, enable: true, ipv6: false, listen: "127.0.0.1:1053",
    "prefer-h3": false, "respect-rules": true,
    "default-nameserver": [direct],
    "proxy-server-nameserver": [direct],
    "proxy-server-nameserver-policy": nodePolicy,
    "nameserver-policy": {}, nameserver: general, fallback: [],
    "direct-nameserver": [direct], "direct-nameserver-follow-policy": false};
  // The app's TUN settings remain authoritative and are saved separately.
  config.tun = {...(config.tun || {}), "dns-hijack": ["any:53", "tcp://any:53"], "strict-route": true};
  config.mode = "rule";
  config.profile = {...(config.profile || {}), "store-selected": true};
  return config;
}
