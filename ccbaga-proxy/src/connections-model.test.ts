import {test, expect} from 'bun:test';
import {merge, offChain, type Snapshot} from './connections-model';
const snapshot = (observed_at: number, connections: Snapshot['connections'], readable = true): Snapshot =>
  ({schema:1, available:true, observed_at, readable, mode:'claude', connections});
const api = {source:'fixed_port' as const, host:'api.anthropic.com', port:443, fixed:true, route:null};
const direct = {source:'desktop' as const, host:'claude.ai', port:443, fixed:false, route:'DIRECT'};
test('each target is kept once with first and last seen, off-chain first', () => {
  let seen = merge([], snapshot(1000, [api]));
  seen = merge(seen, snapshot(3000, [api, direct]));
  expect(seen.map(row => [row.host, row.fixed, row.first, row.last])).toEqual([['claude.ai', false, 3000, 3000], ['api.anthropic.com', true, 1000, 3000]]);
  expect(offChain(seen)).toBe(1);
});
test('the same host on and off the fixed exit are different findings', () => {
  const seen = merge([], snapshot(1000, [api, {...api, source:'cli', fixed:false, route:'DIRECT'}]));
  expect(seen.length).toBe(2);
  expect(offChain(seen)).toBe(1);
});
test('an unreadable Clash keeps what was seen instead of clearing it', () => {
  const seen = merge([], snapshot(1000, [direct]));
  expect(merge(seen, snapshot(2000, [], false))).toBe(seen);
});
