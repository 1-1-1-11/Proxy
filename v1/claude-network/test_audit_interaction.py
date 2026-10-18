"""Offline menu/confirmation regressions; never load the real repair backend."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

import audit_proxy as audit


INSTALL = Path('synthetic-install')
WORKSPACE = Path('synthetic-workspace')


def report(marker='initial'):
    return {'state': 'ENVIRONMENT_READY', 'ready': True, 'exit_code': 0,
            'read_only': True, 'mode': 'check', 'checks': [],
            'limitations': [], 'test_marker': marker}


def option(available=True):
    return {'id': 'synthetic-repair', 'title': '测试修复方案',
            'available': available, 'reason': '' if available else '测试条件不满足',
            'changes': ['仅模拟一次受确认的修改'], 'impact': '模拟影响',
            'expected': '模拟预期结果', 'rollback': '模拟恢复方法'}


class TtyBuffer(io.StringIO):
    def isatty(self):
        return True


class OfflineInteractionCase(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        # The real repair module must not even be imported. Its public interface
        # is deliberately represented by simple call-recording mocks.
        self.actions = types.ModuleType('audit_actions')
        self.actions.repair_options = mock.Mock(return_value=[option()])
        self.actions.execute_option = mock.Mock(return_value={
            'exit_code': 0, 'message': '模拟修复完成', 'backup': 'synthetic-backup',
            'rollback_command': 'synthetic-rollback'})
        self.stack.enter_context(mock.patch.dict(sys.modules, {'audit_actions': self.actions}))
        self.collect = self.stack.enter_context(mock.patch.object(
            audit, 'collect', side_effect=lambda *args, **kwargs: report('rechecked')))
        self.display = self.stack.enter_context(mock.patch.object(audit, 'display'))
        self.stack.enter_context(mock.patch.object(
            audit, 'run', side_effect=AssertionError('Real process execution forbidden')))
        self.stack.enter_context(mock.patch.object(
            audit, 'api', side_effect=AssertionError('Real controller access forbidden')))
        self.stack.enter_context(mock.patch.object(
            audit.subprocess, 'Popen', side_effect=AssertionError('Real process launch forbidden')))
        self.stack.enter_context(mock.patch.object(
            audit.socket, 'socket', side_effect=AssertionError('Real network socket forbidden')))
        if sys.platform == 'win32':
            import winreg
            self.stack.enter_context(mock.patch.object(
                winreg, 'OpenKey', side_effect=AssertionError('Real registry access forbidden')))
        self.args = types.SimpleNamespace(install_dir=INSTALL, workspace=WORKSPACE,
                                          full=False, runtime=False, details=False)

    def menu(self, responses, initial=None):
        initial = report() if initial is None else initial
        output = io.StringIO()
        with mock.patch('builtins.input', side_effect=responses), contextlib.redirect_stdout(output):
            result = audit.interactive(initial, self.args)
        return result, output.getvalue()


class InteractiveRepairTests(OfflineInteractionCase):
    def test_view_options_then_return_does_not_execute(self):
        initial = report()
        result, output = self.menu(['R', '', 'Q'], initial)
        self.actions.repair_options.assert_called_once_with(initial, INSTALL)
        self.actions.execute_option.assert_not_called()
        self.collect.assert_not_called()
        self.assertIs(result, initial)
        self.assertTrue(result['read_only'])
        self.assertIn('测试修复方案', output)

    def test_view_selected_plan_then_cancel_does_not_execute(self):
        initial = report()
        result, output = self.menu(['R', '1', '', 'Q'], initial)
        self.actions.execute_option.assert_not_called()
        self.collect.assert_not_called()
        self.assertIs(result, initial)
        for detail in ('仅模拟一次受确认的修改', '模拟影响', '模拟预期结果', '模拟恢复方法'):
            self.assertIn(detail, output)
        self.assertIn('已取消', output)

    def test_unavailable_option_does_not_ask_for_confirmation_or_execute(self):
        self.actions.repair_options.return_value = [option(available=False)]
        result, output = self.menu(['R', '1', 'Q'])
        self.actions.execute_option.assert_not_called()
        self.collect.assert_not_called()
        self.assertTrue(result['read_only'])
        self.assertIn('该方案当前不能自动执行', output)

    def test_only_exact_uppercase_yes_authorizes_execution(self):
        for answer in ('yes', 'Yes', 'yEs', 'Y', 'YES please', 'YES!', 'NO', '确认'):
            with self.subTest(answer=answer):
                self.actions.execute_option.reset_mock()
                self.collect.reset_mock()
                result, _ = self.menu(['R', '1', answer, 'Q'])
                self.actions.execute_option.assert_not_called()
                self.collect.assert_not_called()
                self.assertTrue(result['read_only'])

    def test_yes_executes_selected_option_then_collects_fresh_report(self):
        events = []
        self.actions.execute_option.side_effect = lambda *args: (
            events.append('execute') or {'exit_code': 0, 'message': '模拟修复完成'})
        self.collect.side_effect = lambda *args, **kwargs: events.append('collect') or report('after-repair')
        result, _ = self.menu(['R', '1', 'YES', 'Q'])
        self.assertEqual(events, ['execute', 'collect'])
        self.actions.execute_option.assert_called_once_with('synthetic-repair', INSTALL, WORKSPACE)
        self.collect.assert_called_once_with(INSTALL, WORKSPACE, False, runtime=False)
        self.assertEqual(result['test_marker'], 'after-repair')
        self.assertFalse(result['read_only'])
        self.assertEqual(result['repair']['option'], 'synthetic-repair')
        self.assertTrue(result['repair']['requested'])
        self.assertEqual(result['repairs'], [result['repair']])

    def test_check_again_after_repair_preserves_write_history(self):
        self.collect.side_effect = [report('after-repair'), report('after-manual-recheck')]
        result, _ = self.menu(['R', '1', 'YES', 'C', 'Q'])
        self.assertEqual(self.collect.call_count, 2)
        self.actions.execute_option.assert_called_once()
        self.assertEqual(result['test_marker'], 'after-manual-recheck')
        self.assertFalse(result['read_only'])
        self.assertTrue(result['repair']['requested'])
        self.assertEqual(result['repair']['option'], 'synthetic-repair')
        self.assertEqual(result['repair']['backup'], 'synthetic-backup')
        self.assertEqual(result['repairs'], [result['repair']])

    def test_check_again_preserves_preexisting_legacy_repair_record(self):
        initial = report()
        initial.update(read_only=False, repair={'requested': True, 'backend_exit': 0})
        expected = copy.deepcopy(initial['repair'])
        result, _ = self.menu(['C', 'Q'], initial)
        self.actions.execute_option.assert_not_called()
        self.assertFalse(result['read_only'])
        self.assertEqual(result['repair'], expected)

    def test_interrupt_during_repair_or_recheck_never_returns_old_ready(self):
        for interrupted_step in ('execute', 'collect'):
            with self.subTest(interrupted_step=interrupted_step):
                initial = report()

                def execute(*args):
                    # The write intent must be recorded before calling a backend
                    # which may change state and then raise KeyboardInterrupt.
                    self.assertFalse(initial['read_only'])
                    self.assertEqual(initial['repair']['state'], 'in_progress')
                    self.assertEqual(initial['repairs'], [initial['repair']])
                    if interrupted_step == 'execute':
                        raise KeyboardInterrupt
                    return {'exit_code': 0, 'message': '模拟修复完成'}

                self.actions.execute_option.side_effect = execute
                self.collect.side_effect = KeyboardInterrupt
                result, _ = self.menu(['R', '1', 'YES'], initial)
                self.assertFalse(result['read_only'])
                self.assertFalse(result['ready'])
                self.assertEqual(result['state'], 'INCOMPLETE')
                self.assertEqual(result['exit_code'], 3)
                self.assertEqual(result['repair']['state'], 'interrupted')
                self.assertEqual(result['repairs'], [result['repair']])
                interrupted = [check for check in result['checks'] if check['id'] == 'repair_interrupted']
                self.assertEqual(len(interrupted), 1)
                self.assertTrue(interrupted[0]['required'])
                self.assertEqual(interrupted[0]['status'], 'unknown')

    def test_manual_recheck_preserves_runtime_selection(self):
        self.args.full, self.args.runtime = True, True
        self.menu(['C', 'Q'])
        self.collect.assert_called_once_with(INSTALL, WORKSPACE, True, runtime=True)
        self.actions.execute_option.assert_not_called()

    def test_eof_at_menu_plan_selection_or_confirmation_never_executes(self):
        for responses in ([EOFError], ['R', EOFError], ['R', '1', EOFError]):
            with self.subTest(responses=responses):
                self.actions.execute_option.reset_mock()
                self.collect.reset_mock()
                initial = report()
                result, output = self.menu(responses, initial)
                self.actions.execute_option.assert_not_called()
                self.collect.assert_not_called()
                self.assertIs(result, initial)
                self.assertIn('已结束交互', output)


class NoninteractiveMainTests(OfflineInteractionCase):
    def invoke(self, flags):
        output = TtyBuffer()
        with mock.patch.object(sys, 'argv', ['audit_proxy.py', *flags]), \
             mock.patch.object(sys, 'stdin', TtyBuffer()), \
             mock.patch.object(sys, 'stdout', output), \
             mock.patch.object(audit, 'interactive', side_effect=AssertionError('Menu forbidden')) as menu, \
             mock.patch('builtins.input', side_effect=AssertionError('Input forbidden')) as input_mock:
            code = audit.main()
        menu.assert_not_called()
        input_mock.assert_not_called()
        self.actions.execute_option.assert_not_called()
        self.assertEqual(code, 0)
        return output.getvalue()

    def test_json_never_enters_menu_even_with_tty_input_and_output(self):
        result = json.loads(self.invoke(['--json']))
        self.assertTrue(result['read_only'])
        self.assertEqual(result['state'], 'ENVIRONMENT_READY')
        self.display.assert_not_called()
        self.collect.assert_called_once()

    def test_no_prompt_never_enters_menu_even_with_tty_input_and_output(self):
        self.invoke(['--no-prompt'])
        self.display.assert_called_once()
        self.collect.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
