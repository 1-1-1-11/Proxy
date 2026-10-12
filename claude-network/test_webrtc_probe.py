"""Native WebRTC regression checks with fake policies, ICE and UDP evidence.

No browser, live STUN socket, process scan or proxy API is used. The optional
Node test executes ICE_JS with a synthetic RTCPeerConnection, never networking.
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import types
import unittest
from unittest import mock

import webrtc_probe as probe

EXPECTED = '203.0.113.10'
FOREIGN = '8.8.8.8'
CANARY = 'PRIVATE_PREF_SDP_CANARY'


def finish(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as ended:
        return ended.value
    coroutine.close()
    raise AssertionError('Fake WebRTC check attempted real asynchronous IO')


def prefs():
    return {'webrtc': {'ip_handling_policy': {'value': probe.EXPECTED_POLICY, 'metadata': ['managed']},
                       'ip_handling_url': {'value': []}},
            'unrelated_identity': CANARY}


def good_evidence():
    return {'effective_policy': probe.project_policy(prefs()),
            'native_ice': {'offer_created': True, 'completed': True, 'timed_out': False,
                           'candidates': [], 'errors': [], 'states': ['gathering', 'complete']},
            'stun_control': {'ok': True, 'mapped_ip': FOREIGN},
            'owned_browser_udp': {'readable': True, 'records': []}}


class PolicyProjectionTests(unittest.TestCase):
    def test_nested_and_dotted_policy_names_project_equally(self):
        raw = prefs()
        flat = {'webrtc.ip_handling_policy': raw['webrtc']['ip_handling_policy'],
                'webrtc.ip_handling_url': raw['webrtc']['ip_handling_url']}
        self.assertEqual(probe.project_policy(raw), probe.project_policy(flat))

    def test_private_preferences_and_url_patterns_never_leave_projection(self):
        raw = prefs()
        raw['webrtc']['ip_handling_policy']['metadata'].append(CANARY)
        raw['webrtc']['ip_handling_url']['value'] = [{'url': 'https://' + CANARY, 'handling': 'default'}]
        projected = probe.project_policy(raw)
        self.assertEqual(projected['url_override_count'], 1)
        self.assertFalse(projected['url_overrides_empty'])
        self.assertNotIn(CANARY, json.dumps(projected))

    def test_absent_or_unknown_policy_does_not_become_protective(self):
        for raw in ({}, {'webrtc': {'ip_handling_policy': {'value': CANARY}}}):
            projected = probe.project_policy(raw)
            self.assertEqual(projected['value'], 'unrecognized')
            self.assertFalse(projected['url_overrides_empty'])
            self.assertNotIn(CANARY, json.dumps(projected))

    def test_actual_chrome_store_metadata_is_retained_without_private_fields(self):
        for source in ('command_line_controlled', 'extension_controlled',
                       'user_controlled', 'recommended', 'managed_by_custodian'):
            raw = prefs()
            raw['webrtc']['ip_handling_policy']['metadata'] = [source, 'extension_modifiable', CANARY]
            projected = probe.project_policy(raw)
            self.assertEqual(projected['sources'], [source, 'extension_modifiable'])
            self.assertNotIn(CANARY, json.dumps(projected))


class ClassificationTests(unittest.TestCase):
    def test_valid_managed_policy_completed_ice_control_and_no_udp_pass(self):
        status, _, reason = probe.classify(good_evidence(), EXPECTED)
        self.assertEqual((status, reason), ('pass', 'policy_and_native_ice_verified'))

    def test_missing_or_unprotective_policy_cannot_pass(self):
        for value in (None, 'unrecognized', 'default', 'default_public_interface_only'):
            evidence = good_evidence()
            evidence['effective_policy']['value'] = value
            with self.subTest(value=value):
                self.assertNotEqual(probe.classify(evidence, EXPECTED)[0], 'pass')

    def test_cli_or_user_setting_is_not_managed_proof(self):
        for sources in ([], ['command_line'], ['user_modifiable'], ['extension'],
                        ['command_line_controlled', 'extension_modifiable'],
                        ['extension_controlled', 'extension_modifiable'],
                        ['user_controlled', 'user_modifiable'], ['recommended'],
                        ['extension_modifiable'], ['managed_by_custodian']):
            evidence = good_evidence()
            evidence['effective_policy']['sources'] = sources
            status, _, reason = probe.classify(evidence, EXPECTED)
            self.assertEqual((status, reason), ('unknown', 'profile_scope_unverified'))

    def test_command_line_control_is_not_described_as_extension_control(self):
        evidence = good_evidence()
        evidence['effective_policy']['sources'] = ['command_line_controlled', 'extension_modifiable']
        status, detail, reason = probe.classify(evidence, EXPECTED)
        self.assertEqual((status, reason), ('unknown', 'profile_scope_unverified'))
        self.assertIn('由命令行控制', detail)
        self.assertNotIn('由扩展控制', detail)

    def test_command_line_passes_only_with_clean_readable_profile(self):
        clean = {'readable': True, 'capable': [], 'missing_forced': []}
        cases = [(clean, 'pass', None),
                 ({**clean, 'capable': [{'id': 'x', 'name': 'WebRTC Control'}]}, 'unknown', 'WebRTC Control'),
                 ({**clean, 'missing_forced': [{'id': 'y'}]}, 'unknown', '尚未装入'),
                 ({'readable': False}, 'unknown', '无法读取'), ({}, 'unknown', '无法读取')]
        for scope, status, text in cases:
            with self.subTest(scope=scope):
                evidence = good_evidence()
                evidence['effective_policy']['sources'] = ['command_line_controlled', 'extension_modifiable']
                evidence['profile_scope'] = scope
                result, detail, _ = probe.classify(evidence, EXPECTED)
                self.assertEqual(result, status)
                if text:
                    self.assertIn(text, detail)
        evidence = good_evidence()
        evidence['effective_policy']['sources'] = ['extension_controlled']
        evidence['profile_scope'] = clean
        self.assertEqual(probe.classify(evidence, EXPECTED)[0], 'unknown')

    def test_profile_scan_finds_privacy_permission_and_missing_forced_extensions(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'Local State').write_text(json.dumps({'profile': {'info_cache': {'Default': {}, 'Profile 1': {}}}}), encoding='utf-8')
            for name, settings in {'Default': {'a': {'active_permissions': {'api': ['storage']}, 'manifest': {'name': 'Plain'}},
                                               'forced': {'active_permissions': {'api': []}}},
                                   'Profile 1': {'b': {'active_permissions': {'api': ['privacy']}, 'manifest': {'name': 'Leaky'}},
                                                 'c': {'preferences': {'webrtc.ip_handling_policy': 'default'}}},
                                   'System Profile': {}}.items():
                (root / name).mkdir()
                (root / name / 'Secure Preferences').write_text(json.dumps({'extensions': {'settings': settings}}), encoding='utf-8')
            (root / 'System Profile' / 'Preferences').write_text('{}', encoding='utf-8')
            scope = probe.profile_extension_scope(root, forced={'forced'})
            self.assertTrue(scope['readable'])
            self.assertEqual(scope['profiles'], ['Default', 'Profile 1'])
            self.assertEqual(sorted(row['id'] for row in scope['capable']), ['b', 'c'])
            self.assertEqual(scope['missing_forced'], [{'profile': 'Profile 1', 'id': 'forced'}])
            (root / 'Default' / 'Secure Preferences').write_text('{broken', encoding='utf-8')
            self.assertFalse(probe.profile_extension_scope(root, forced=set())['readable'])
        self.assertEqual(probe.profile_extension_scope(Path(folder) / 'absent', forced={'z'})['missing_forced'],
                         [{'profile': None, 'id': 'z'}])

    def test_url_override_missing_or_nonempty_cannot_pass(self):
        for flag in (None, False):
            evidence = good_evidence()
            evidence['effective_policy']['url_overrides_empty'] = flag
            self.assertEqual(probe.classify(evidence, EXPECTED)[2], 'url_override_unverified')

    def test_missing_positive_control_cannot_turn_zero_candidates_into_pass(self):
        for control in ({}, {'ok': False, 'error': 'timeout'}):
            evidence = good_evidence()
            evidence['stun_control'] = control
            self.assertEqual(probe.classify(evidence, EXPECTED)[0], 'unknown')

    def test_ice_offer_completion_timeout_and_error_each_block_pass(self):
        for key, value in (('offer_created', False), ('completed', False), ('timed_out', True), ('error', 'native_ice_error')):
            evidence = good_evidence()
            evidence['native_ice'][key] = value
            with self.subTest(key=key):
                self.assertEqual(probe.classify(evidence, EXPECTED)[2], 'native_ice_incomplete')

    def test_unreadable_browser_udp_cannot_pass(self):
        evidence = good_evidence()
        evidence['owned_browser_udp'] = {'readable': False, 'records': []}
        self.assertEqual(probe.classify(evidence, EXPECTED)[2], 'browser_udp_unreadable')

    def test_owned_stun_udp_is_failure(self):
        evidence = good_evidence()
        evidence['owned_browser_udp']['records'] = [{'source_port': 55555, 'destination_port': 3478}]
        status, _, reason = probe.classify(evidence, EXPECTED)
        self.assertEqual((status, reason), ('fail', 'browser_stun_udp_observed'))

    def test_foreign_public_candidate_fails_even_when_other_evidence_incomplete(self):
        evidence = {'native_ice': {'completed': False, 'candidates': [{'address': FOREIGN, 'type': 'srflx'}]}}
        status, _, reason = probe.classify(evidence, EXPECTED)
        self.assertEqual((status, reason), ('fail', 'foreign_public_candidate'))

    def test_private_candidate_warns_and_is_not_called_public_leak(self):
        evidence = good_evidence()
        evidence['native_ice']['candidates'] = [{'address': '192.168.1.20', 'type': 'host'}]
        self.assertEqual(probe.classify(evidence, EXPECTED)[0], 'warn')
        self.assertEqual(evidence['public_candidate_ips'], [])


class OwnedUdpTests(unittest.TestCase):
    def scan(self, root_pids=(123,), error=None):
        def process(pid):
            if error: raise error
            return types.SimpleNamespace(children=lambda recursive: [types.SimpleNamespace(pid=456)])
        def connection(pid, port):
            return types.SimpleNamespace(pid=pid, laddr=types.SimpleNamespace(port=port))
        psutil = types.SimpleNamespace(Process=process, NoSuchProcess=ProcessLookupError,
            net_connections=lambda kind: [connection(123, 55001), connection(456, 55002), connection(999, 55003)])
        def record(source, *, network='udp', destination=3478):
            return {'metadata': {'network': network, 'sourcePort': str(source), 'destinationPort': str(destination)},
                    'rule': 'SyntheticRule', 'chains': ['SyntheticChain']}
        proxy = types.SimpleNamespace(api=lambda path: {'connections': [record(55001), record(55002),
            record(55003), record(55001, network='tcp'), record(55002, destination=443)]})
        with mock.patch.dict(sys.modules, {'psutil': psutil, 'audit_proxy': proxy}):
            return probe.owned_udp_records(list(root_pids))

    def test_only_test_browser_tree_stun_udp_is_collected(self):
        result = self.scan()
        self.assertTrue(result['readable'])
        self.assertEqual(result['browser_pids'], [123, 456])
        self.assertEqual({row['source_port'] for row in result['records']}, {'55001', '55002'})
        self.assertEqual(len(result['records']), 2)

    def test_empty_ownership_and_permission_error_are_unreadable(self):
        self.assertFalse(self.scan(root_pids=())['readable'])
        self.assertFalse(self.scan(error=PermissionError('synthetic'))['readable'])


class FakePage:
    def __init__(self, *, raw_prefs=None, ice=None, trace_ip=EXPECTED, fail=False):
        self.raw_prefs = prefs() if raw_prefs is None else raw_prefs
        self.ice = good_evidence()['native_ice'] if ice is None else ice
        self.trace_ip, self.fail = trace_ip, fail
        self.url, self.closed, self.peer_closed = '', False, False
    async def goto(self, url, **kwargs):
        self.url = url
        if self.fail: raise RuntimeError(CANARY)
    async def wait_for_function(self, *args, **kwargs): pass
    def locator(self, selector): return self
    async def inner_text(self):
        return json.dumps(self.raw_prefs) if self.url == 'chrome://prefs-internals' else 'ip=' + self.trace_ip
    async def evaluate(self, script, *args):
        if script == probe.ICE_JS: return copy.deepcopy(self.ice)
        self.peer_closed = True
    async def close(self): self.closed = True


class NativeCheckTests(unittest.TestCase):
    def run_check(self, page, *, control=None, udp=None, scope=None):
        async def cdp_send(command): return {'processInfo': [{'type': 'browser', 'id': 123}, {'type': 'renderer', 'id': 999}]}
        async def new_cdp(): return types.SimpleNamespace(send=cdp_send)
        async def new_page(): return page
        async def to_thread(function, *args): return function(*args)
        async def gather(*coroutines): return [await coroutine for coroutine in coroutines]
        async def sleep(duration): pass
        context = types.SimpleNamespace(browser=types.SimpleNamespace(new_browser_cdp_session=new_cdp), new_page=new_page)
        stun = types.SimpleNamespace(probe_stun=mock.Mock(return_value={'ok': True} if control is None else control))
        reader = mock.Mock(side_effect=udp) if isinstance(udp, list) else mock.Mock(return_value=udp or {'readable': True, 'records': []})
        with mock.patch.dict(sys.modules, {'stun_probe': stun}), \
             mock.patch.object(probe, 'owned_udp_records', reader), \
             mock.patch.object(probe, 'profile_extension_scope', return_value=scope or {'readable': False}), \
             mock.patch.object(probe.asyncio, 'to_thread', new=to_thread), \
             mock.patch.object(probe.asyncio, 'gather', new=gather), \
             mock.patch.object(probe.asyncio, 'sleep', new=sleep):
            result = finish(probe.native_check(context, EXPECTED))
        self.assertTrue(page.closed)
        self.assertTrue(page.peer_closed)
        return result, reader

    def test_completed_native_check_projects_preferences_and_masks_mdns(self):
        ice = good_evidence()['native_ice']
        ice['candidates'] = [{'address': CANARY + '.local', 'type': 'host', 'protocol': 'udp'}]
        (status, _, evidence), reader = self.run_check(FakePage(ice=ice))
        self.assertEqual(status, 'pass')
        self.assertNotIn(CANARY, json.dumps(evidence))
        self.assertEqual(evidence['native_ice']['candidates'][0]['address'], '<mdns-or-unparsed>')
        self.assertEqual(reader.call_count, 4)
        self.assertTrue(all(call.args == ([123],) for call in reader.call_args_list))

    def test_final_udp_sample_can_fail_otherwise_clean_observation(self):
        empty = {'readable': True, 'records': []}
        last = {'readable': True, 'records': [{'source_port': 55555, 'destination_port': 3478}]}
        (status, _, evidence), _ = self.run_check(FakePage(), udp=[empty, empty, empty, last])
        self.assertEqual((status, evidence['reason']), ('fail', 'browser_stun_udp_observed'))

    def test_completed_ice_with_only_command_line_policy_remains_unknown(self):
        raw = prefs()
        raw['webrtc']['ip_handling_policy']['metadata'] = ['command_line_controlled', 'extension_modifiable']
        (status, detail, evidence), _ = self.run_check(FakePage(raw_prefs=raw))
        self.assertEqual((status, evidence['reason']), ('unknown', 'profile_scope_unverified'))
        self.assertEqual(evidence['effective_policy']['sources'],
                         ['command_line_controlled', 'extension_modifiable'])
        self.assertIn('由命令行控制', detail)

    def test_completed_ice_with_command_line_and_clean_profile_passes(self):
        raw = prefs()
        raw['webrtc']['ip_handling_policy']['metadata'] = ['command_line_controlled', 'extension_modifiable']
        clean = {'readable': True, 'profiles': ['Default'], 'capable': [], 'missing_forced': []}
        (status, detail, evidence), _ = self.run_check(FakePage(raw_prefs=raw), scope=clean)
        self.assertEqual((status, evidence['reason']), ('pass', 'policy_and_native_ice_verified'))
        self.assertIn('没有能覆盖它的扩展', detail)

    def test_positive_control_failure_and_trace_mismatch_are_not_pass(self):
        (status, _, _), _ = self.run_check(FakePage(), control={'ok': False})
        self.assertEqual(status, 'unknown')
        (status, _, evidence), _ = self.run_check(FakePage(trace_ip=FOREIGN))
        self.assertEqual((status, evidence['reason']), ('fail', 'browser_http_exit_mismatch'))

    def test_exception_is_unknown_redacted_and_closes_owned_page(self):
        (status, _, evidence), _ = self.run_check(FakePage(fail=True))
        self.assertEqual(status, 'unknown')
        self.assertNotIn(CANARY, json.dumps(evidence))
        self.assertEqual(evidence['error'], 'RuntimeError')


class IceScriptProjectionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Installed Node required for offline JavaScript execution')
    def test_offer_sdp_and_opaque_candidate_fields_do_not_leave_ice_script(self):
        harness = r'''const fs=require('fs');const req=JSON.parse(fs.readFileSync(0,'utf8'));
global.window={};
global.RTCPeerConnection=class {
 createDataChannel(){}
 async createOffer(){return {type:'offer',sdp:'v=0\r\n'+req.marker};}
 async setLocalDescription(offer){this.localDescription=offer;
  this.onicecandidate({candidate:{type:'host',protocol:'udp',address:'192.168.1.20',port:12345,relatedPort:null,candidate:req.marker,sdp:req.marker}});
  this.iceGatheringState='complete';this.onicegatheringstatechange();}
 close(){}
};
(async()=>{const run=eval('('+req.script+')');const result=await run({host:'synthetic.invalid',port:3478});process.stdout.write(JSON.stringify(result));})().catch(()=>process.exit(1));'''
        run = subprocess.run([shutil.which('node'), '-e', harness],
            input=json.dumps({'script': probe.ICE_JS, 'marker': CANARY}),
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5,
            creationflags=0x08000000 if os.name == 'nt' else 0)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn(CANARY, run.stdout)
        result = json.loads(run.stdout)
        self.assertTrue(result['completed'])
        self.assertTrue(result['offer_created'])
        self.assertEqual(result['candidates'][0]['address'], '192.168.1.20')
        self.assertNotIn('sdp', result)
        self.assertNotIn('candidate', result['candidates'][0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
