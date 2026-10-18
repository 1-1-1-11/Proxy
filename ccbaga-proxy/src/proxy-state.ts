// Cached UI evidence never grants native permission: every launch checks again.
// So an expired result only turns the display neutral; it never locks a launch button.
export type Verdict = 'ready' | 'blocked' | 'unknown' | 'not_installed';
// 'browser' is the web entry (the fingerprint browser's own gate); 'web' is Proxy-v2's login-link launcher.
export type Entry = 'cli' | 'vscode' | 'web' | 'desktop' | 'browser';
export interface ProxyStatus {
  schema: 1; available: boolean; observed_at: number; version: string;
  workspace: string; endpoint: string; expected_ip: string;
  guard: {state: Verdict; age_seconds: number | null; blocked: boolean; repair_active: boolean;
    // Alive but silent past its limit (after sleep); what it last saw of Claude connections and Clash.
    recovering?: boolean; offchain?: number | null; mode?: 'rule' | 'global' | 'direct' | null; tun?: boolean | null};
}
export type Protection = 'protected' | 'needs_protect' | 'firewall_off' | 'not_installed' | 'unknown';
export interface ProxyReport extends ProxyStatus {
  checked_at: number; entries: Partial<Record<Entry, Verdict>>; observed_ips: string[];
  checks: {id: string; title: string; state: Verdict; detail?: string; entries: Entry[]}[];
  // Connections of programs already running; reported apart, they do not decide new launches.
  running?: {state: Verdict; entries: Entry[]} | null;
  // Whether Proxy-v2's -Protect would help the desktop app; only full and desktop checks carry it.
  desktop_protection?: Protection;
}
export function fresh(report: ProxyReport | null, status: ProxyStatus | null, now: number): boolean {
  return !!report && !!status && status.available === true && report.available === true
    && now >= report.checked_at && now - report.checked_at <= 60_000
    && now >= status.observed_at && now - status.observed_at <= 15_000
    && status.endpoint === report.endpoint && status.expected_ip === report.expected_ip;
}
export function entryVerdict(entry: Entry, report: ProxyReport | null, status: ProxyStatus | null, now: number, error = ''): Verdict {
  if (error || !fresh(report, status, now)) return 'unknown';
  if (report?.entries[entry] === 'not_installed') return 'not_installed';
  if (status?.guard.state !== 'ready') return status?.guard.state === 'blocked' ? 'blocked' : 'unknown';
  return report?.entries[entry] ?? 'unknown';
}
// Only a current, explicit refusal disables the button; unknown means "the click will check".
export function canLaunch(verdict: Verdict): boolean {
  return verdict !== 'blocked' && verdict !== 'not_installed';
}
// Problems that need the user now without deciding new launches: programs already running off the
// fixed exit (from the current check, else from the watchdog), and Clash outside Rule mode, where
// claude.ai in an ordinary browser no longer follows the fixed exit.
export function alerts(report: ProxyReport | null, status: ProxyStatus | null, now: number) {
  const running = fresh(report, status, now) && report?.running?.state === 'blocked' ? report.running.entries : null;
  return {running, offchain: !running && (status?.guard.offchain ?? 0) > 0,
    mode: !!status?.guard.mode && status.guard.mode !== 'rule'};
}
// Titles of the checks that did not pass, without duplicates, in report order.
export function failing(report: ProxyReport | null): string[] {
  return [...new Set((report?.checks ?? []).filter(check => check.state !== 'ready').map(check => check.title))];
}

// ----- Environment consistency: the computer and the fingerprint browser follow the fixed exit -----
export type ExitRegion = {country:string; timezone:string; region:string|null; label:string|null};
export type Computer = {timezone:string; location_enabled:boolean|null};
export type BrowserView = {running:boolean; config:{follow_machine:boolean; language:string; timezone:string};
  machine:{timezone:string; languages:string[]}; report:{language:string; timezone:string; exit:{country:string}|null; error:string}|null;
  report_received_at:number|null};
export type Consistency = 'ok' | 'attention' | 'unknown';
// The browser's own setting; the language a traveler uses with the exit's time zone is English.
export const BROWSER_LANGUAGE = 'en-US';
export function browserSetting(browser: BrowserView) {
  const first = browser.machine.languages[0] ?? BROWSER_LANGUAGE;
  return browser.config.follow_machine
    ? {timezone:browser.machine.timezone, language:first === 'en' ? BROWSER_LANGUAGE : first}
    : {timezone:browser.config.timezone, language:browser.config.language};
}
// Each row is judged against the fixed exit; nothing is green without both sides known.
export function environment(exit: ExitRegion | null, computer: Computer | null, browser: BrowserView | null) {
  const judge = (known: boolean, ok: boolean): Consistency => !known ? 'unknown' : ok ? 'ok' : 'attention';
  const setting = browser && browserSetting(browser);
  const report = browser?.running && browser.report && !browser.report.error ? browser.report : null;
  const differences = report && exit && computer ? [
    report.exit?.country !== exit.country && '出口国家',
    report.timezone !== exit.timezone && '浏览器时区',
    computer.timezone !== exit.timezone && '系统时区',
    report.language !== BROWSER_LANGUAGE && '浏览器语言',
  ].filter((item): item is string => !!item) : [];
  return {
    system: judge(!!exit && !!computer, computer?.timezone === exit?.timezone),
    browser: judge(!!exit && !!setting, setting?.timezone === exit?.timezone && setting?.language === BROWSER_LANGUAGE),
    location: judge(computer?.location_enabled != null, computer?.location_enabled === false),
    measured: judge(!!report && !!exit && !!computer, differences.length === 0),
    setting, report, differences,
  };
}
