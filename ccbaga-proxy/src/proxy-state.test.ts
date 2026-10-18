import {test, expect} from 'bun:test';
import {alerts, browserSetting, canLaunch, entryVerdict, environment, failing, fresh, type ProxyReport} from './proxy-state';
const report: ProxyReport = {schema:1, available:true, observed_at:10_000, checked_at:10_000, version:'test', workspace:'test', endpoint:'http://127.0.0.1:17892', expected_ip:'203.0.113.7', observed_ips:['203.0.113.7'], guard:{state:'ready', age_seconds:0, blocked:false, repair_active:false}, entries:{cli:'ready'}, checks:[]};
test('old full audit and stale heartbeat both revoke readiness', () => {
  expect(fresh(report, {...report, observed_at:70_001}, 70_001)).toBe(false);
  expect(fresh(report, report, 25_001)).toBe(false);
  expect(entryVerdict('cli', report, report, 12_000)).toBe('ready');
});
test('errors, missing entry, policy change and blocked guard never reuse old green', () => {
  expect(entryVerdict('cli', report, report, 12_000, 'timeout')).toBe('unknown');
  expect(entryVerdict('web', report, report, 12_000)).toBe('unknown');
  expect(entryVerdict('browser', report, report, 12_000)).toBe('unknown');
  expect(entryVerdict('browser', {...report, entries:{browser:'ready', web:'blocked'}}, report, 12_000)).toBe('ready');
  expect(entryVerdict('cli', report, {...report, expected_ip:'203.0.113.8'}, 12_000)).toBe('unknown');
  expect(entryVerdict('cli', report, {...report, guard:{...report.guard, state:'blocked'}}, 12_000)).toBe('blocked');
});
test('clock moving backwards cannot extend a cached permit', () => {
  expect(entryVerdict('cli', report, report, 9_000)).toBe('unknown');
});
test('only a current refusal locks launch; expired or unknown results leave the native check to decide', () => {
  expect(canLaunch(entryVerdict('cli', report, report, 70_001))).toBe(true);
  expect(canLaunch(entryVerdict('cli', report, report, 12_000, 'timeout'))).toBe(true);
  expect(canLaunch(entryVerdict('cli', report, {...report, guard:{...report.guard, state:'blocked'}}, 12_000))).toBe(false);
  expect(canLaunch(entryVerdict('desktop', {...report, entries:{desktop:'not_installed'}}, report, 12_000))).toBe(false);
});
test('a recovering watchdog is neutral and leaves launch to the native wait', () => {
  const recovering = {...report, guard:{...report.guard, state:'unknown' as const, recovering:true}};
  expect(entryVerdict('cli', report, recovering, 12_000)).toBe('unknown');
  expect(canLaunch(entryVerdict('cli', report, recovering, 12_000))).toBe(true);
});
test('running connections and Clash mode alert without touching launch verdicts', () => {
  expect(alerts(report, report, 12_000)).toEqual({running:null, offchain:false, mode:false});
  const off = {...report, running:{state:'blocked' as const, entries:['cli' as const]}};
  expect(alerts(off, off, 12_000).running).toEqual(['cli']);
  expect(entryVerdict('cli', off, off, 12_000)).toBe('ready');
  // An expired check no longer speaks for running programs; the watchdog's count still does.
  const watched = {...report, guard:{...report.guard, offchain:2}};
  expect(alerts(off, watched, 80_000)).toEqual({running:null, offchain:true, mode:false});
  expect(alerts(report, {...report, guard:{...report.guard, mode:'global'}}, 12_000).mode).toBe(true);
  expect(alerts(report, {...report, guard:{...report.guard, mode:null}}, 12_000).mode).toBe(false);
});
test('failing lists each unpassed check once, in report order', () => {
  const rows = [{id:'route', title:'实际路由', state:'blocked', entries:[]}, {id:'guard', title:'使用中守护', state:'ready', entries:[]},
    {id:'traffic', title:'实际路由', state:'unknown', entries:[]}, {id:'fixed_egress', title:'固定出口 IP', state:'unknown', entries:[]}] as ProxyReport['checks'];
  expect(failing({...report, checks:rows})).toEqual(['实际路由', '固定出口 IP']);
  expect(failing(null)).toEqual([]);
});
test('environment follows the fixed exit: system and browser time zones, English browser, location off', () => {
  const exit = {country:'JP', timezone:'Asia/Tokyo', region:'jp', label:'日本 · 东京'};
  const browser = {running:true, config:{follow_machine:false, language:'en-US', timezone:'Asia/Tokyo'},
    machine:{timezone:'Asia/Tokyo', languages:['zh-Hans']},
    report:{language:'en-US', timezone:'Asia/Tokyo', exit:{country:'JP'}, error:''}, report_received_at:1};
  const computer = {timezone:'Asia/Tokyo', location_enabled:false};
  const good = environment(exit, computer, browser);
  expect([good.system, good.browser, good.location, good.measured]).toEqual(['ok', 'ok', 'ok', 'ok']);
  const drifted = environment(exit, {timezone:'Asia/Shanghai', location_enabled:true}, browser);
  expect([drifted.system, drifted.location, drifted.measured]).toEqual(['attention', 'attention', 'attention']);
  expect(drifted.differences).toEqual(['系统时区']);
  // A browser still following the computer (never started since following the exit) is not aligned yet.
  const following = {...browser, config:{...browser.config, follow_machine:true}, machine:{timezone:'Asia/Shanghai', languages:['zh-Hans']}};
  expect(browserSetting(following)).toEqual({timezone:'Asia/Shanghai', language:'zh-Hans'});
  expect(environment(exit, computer, following).browser).toBe('attention');
  // Unknown sides never turn green; a closed browser has no current measurement.
  const unknown = environment(null, null, null);
  expect([unknown.system, unknown.browser, unknown.location, unknown.measured]).toEqual(['unknown', 'unknown', 'unknown', 'unknown']);
  expect(environment(exit, computer, {...browser, running:false}).measured).toBe('unknown');
  expect(environment(exit, computer, {...browser, report:{...browser.report, error:'probe failed'}}).measured).toBe('unknown');
  expect(environment(exit, {timezone:'Asia/Tokyo', location_enabled:null}, browser).location).toBe('unknown');
});
