// [INPUT]: Read-only snapshots of Claude's live connections through Clash from the native bridge.
// [OUTPUT]: The distinct targets seen while the page is open, off-chain first, with first/last seen times.
// [POS]: Pure presentation state for the connection monitor; it never decides a launch.
export type Source = 'fixed_port' | 'cli' | 'vscode' | 'desktop';
export type Connection = {source:Source; host:string; port:number|null; fixed:boolean; route:string|null};
export type Snapshot = {schema:1; available:boolean; observed_at:number; readable:boolean;
  mode:'claude'|'domestic'|'abnormal'|null; connections:Connection[]};
export type Seen = Connection & {first:number; last:number};
const LIMIT = 500;
const key = (c: Connection) => `${c.source}|${c.host}|${c.port ?? ''}|${c.fixed}`;
// Like Proxy-v2's -Watch: each distinct target once; what left the fixed exit stays on top.
export function merge(seen: Seen[], snapshot: Snapshot): Seen[] {
  if (!snapshot.readable) return seen;
  const rows = new Map(seen.map(row => [key(row), row]));
  for (const c of snapshot.connections) {
    const old = rows.get(key(c));
    rows.set(key(c), old ? {...old, last:snapshot.observed_at} : {...c, first:snapshot.observed_at, last:snapshot.observed_at});
  }
  return [...rows.values()].sort((a, b) => Number(a.fixed) - Number(b.fixed) || b.last - a.last).slice(0, LIMIT);
}
export function offChain(seen: Seen[]): number {
  return seen.filter(row => !row.fixed).length;
}
