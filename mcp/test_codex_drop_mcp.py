"""Tests for the Screenshot Drop MCP server (#220). A fake CLI runner, plus one real `doctor` call."""
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import codex_drop_mcp as m  # noqa: E402


class Fixture(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp()) / 'stores'
        self.root.mkdir()
        self.calls = []
        self.output = '{"ok": true, "state": "complete"}'

    def fake_run(self, argv, **kw):
        self.calls.append((argv, kw))
        return type('P', (), {'stdout': self.output, 'returncode': 0})()

    def server(self, run=None):
        return m.DropServer(run=run or self.fake_run, agent=pathlib.Path('/opt/drop/bin/codex-drop-agent'),
                            python='/usr/bin/python3', root=self.root)


class Calls(Fixture):
    def test_run_passes_the_request_unchanged_on_stdin_with_an_argv_list(self):
        request = {'schema': 1, 'task_id': 't1', 'operation': 'inspect'}
        out = self.server().call('drop_run', {'store': str(self.root / 't1'), 'request': request})
        self.assertFalse(out['isError'])
        argv, kw = self.calls[0]
        self.assertEqual(argv, ['/usr/bin/python3', '-I', '-B', '/opt/drop/bin/codex-drop-agent', 'run',
                                '--store', str(self.root / 't1'), '--request-file', '-'])
        self.assertEqual(json.loads(kw['input']), request)
        self.assertNotIn('shell', kw)

    def test_receipt_and_doctor_map_to_the_cli(self):
        s = self.server()
        s.call('drop_receipt', {'store': str(self.root / 't1'), 'task': 't1', 'operation': 'ingest-001'})
        s.call('drop_doctor', {})
        self.assertEqual(self.calls[0][0][4:], ['receipt', '--store', str(self.root / 't1'), '--task', 't1',
                                                '--operation', 'ingest-001'])
        self.assertEqual(self.calls[1][0][4:], ['doctor'])

    def test_stores_outside_the_root_or_relative_are_refused_before_the_cli(self):
        s = self.server()
        for store in ('relative/store', '/tmp/elsewhere', str(self.root / '..' / 'escape'), ''):
            out = json.loads(s.call('drop_run', {'store': store, 'request': {}})['content'][0]['text'])
            self.assertEqual(out['state'], 'refused', store)
        self.assertEqual(self.calls, [])

    def test_a_timeout_is_uncertain_and_never_reruns(self):
        def slow(argv, **kw):
            self.calls.append(argv)
            raise subprocess.TimeoutExpired(argv, 1)
        out = json.loads(self.server(run=slow).call(
            'drop_run', {'store': str(self.root / 't1'), 'request': {'operation': 'ingest'}})['content'][0]['text'])
        self.assertEqual(out['state'], 'uncertain')
        self.assertIn('drop_receipt', out['next'])
        self.assertEqual(len(self.calls), 1)

    def test_cli_refusals_pass_through_and_unknown_arguments_are_refused(self):
        self.output = '{"ok": false, "state": "refused", "error": {"code": "unknown_root"}}'
        out = self.server().call('drop_run', {'store': str(self.root / 't1'), 'request': {}})
        self.assertTrue(out['isError'])
        self.assertEqual(json.loads(out['content'][0]['text'])['error']['code'], 'unknown_root')
        bad = self.server().call('drop_run', {'store': str(self.root / 't1'), 'request': {}, 'shell': True})
        self.assertTrue(bad['isError'])
        self.assertEqual(len(self.calls), 1)

    def test_oversized_requests_are_refused(self):
        out = self.server().call('drop_run', {'store': str(self.root / 't1'),
                                              'request': {'x': 'a' * (m.MAX_REQUEST + 1)}})
        self.assertEqual(json.loads(out['content'][0]['text'])['error']['code'], 'request_too_large')
        self.assertEqual(self.calls, [])


class ReviewFindings(Fixture):
    """Native review findings on PR2 (Standards/Spec FAIL at dd57b780)."""

    def test_a_child_that_ends_without_a_readable_acknowledgement_is_uncertain_not_refused(self):
        for stdout in ('', 'Traceback (most recent call last):', '{"ok": tr', '[1, 2]'):
            self.output = stdout
            out = json.loads(self.server().call('drop_run', {'store': str(self.root / 't1'),
                                                            'request': {'operation': 'ingest'}})['content'][0]['text'])
            self.assertEqual(out['state'], 'uncertain', stdout)
            self.assertIn('drop_receipt', out['next'])
        self.assertEqual(len(self.calls), 4)       # one call each; nothing re-run

    def test_genuine_cli_refusals_are_kept_unchanged(self):
        self.output = '{"ok": false, "state": "refused", "error": {"code": "duplicate_operation"}}'
        out = json.loads(self.server().call('drop_run', {'store': str(self.root / 't1'),
                                                        'request': {}})['content'][0]['text'])
        self.assertEqual((out['state'], out['error']['code']), ('refused', 'duplicate_operation'))

    def run_lines(self, *raw):
        out = io.StringIO()
        m.serve(self.server(), io.StringIO(''.join(line + '\n' for line in raw)), out)
        return [json.loads(l) for l in out.getvalue().splitlines()]

    def test_duplicate_keys_anywhere_are_refused_before_dispatch(self):
        store = str(self.root / 't1')
        line = ('{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"drop_run","arguments":'
                '{"store":"%s","request":{"operation_id":"a","operation_id":"b"}}}}' % store)
        replies = self.run_lines(line)
        self.assertEqual(replies[0]['error']['code'], -32700)
        self.assertEqual(self.calls, [])

    def test_malformed_protocol_fields_get_errors_and_the_session_continues(self):
        bad = [{'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': [], 'arguments': {}}},
               {'jsonrpc': '2.0', 'id': 2, 'method': 'initialize', 'params': 'bad'},
               {'jsonrpc': '2.0', 'id': 3, 'method': 'initialize', 'params': [1, 2]},
               {'jsonrpc': '2.0', 'id': 4, 'method': ['x']},
               {'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call', 'params': {'name': 'drop_doctor', 'arguments': []}},
               {'jsonrpc': '2.0', 'id': 6, 'method': 'tools/call', 'params': {'name': 'drop_doctor', 'arguments': {}}}]
        replies = self.run_lines(*(json.dumps(b) for b in bad))
        self.assertEqual([r['id'] for r in replies], [1, 2, 3, 4, 5, 6])
        self.assertTrue(all('error' in r for r in replies[:5]))
        self.assertIn('result', replies[5])               # still serving after five bad requests

    def test_a_cli_that_cannot_start_is_refused(self):
        def missing(argv, **kw):
            raise m.StartFailed('FileNotFoundError')
        out = json.loads(self.server(run=missing).call('drop_doctor', {})['content'][0]['text'])
        self.assertEqual(out['error']['code'], 'cli_unavailable')

    def test_an_io_error_after_the_cli_started_is_uncertain(self):
        """Native Spec finding on PR2 at 47c9528: an OSError while reading a started child's output is not proof it
        never ran."""
        def broken_pipe(argv, **kw):
            self.calls.append(argv)
            raise BrokenPipeError('read failed after start')
        out = json.loads(self.server(run=broken_pipe).call(
            'drop_run', {'store': str(self.root / 't1'), 'request': {'operation': 'ingest'}})['content'][0]['text'])
        self.assertEqual(out['state'], 'uncertain')
        self.assertEqual(len(self.calls), 1)

    def test_run_cli_separates_start_failure_from_post_start_errors(self):
        class NoStart:
            def __init__(self, *a, **kw):
                raise FileNotFoundError('no python')
        with self.assertRaises(m.StartFailed):
            m.run_cli(['x'], popen=NoStart)
        state = {}

        class Started:
            returncode = None

            def __init__(self, *a, **kw):
                pass

            def communicate(self, input=None, timeout=None):
                raise OSError('pipe read failed')

            def kill(self):
                state['killed'] = True

            def wait(self):
                state['reaped'] = True
        with self.assertRaises(OSError) as raised:
            m.run_cli(['x'], popen=Started)
        self.assertNotIsInstance(raised.exception, m.StartFailed)
        self.assertEqual(state, {'killed': True, 'reaped': True})

        class Slow(Started):
            def communicate(self, input=None, timeout=None):
                raise subprocess.TimeoutExpired('x', timeout)
        with self.assertRaises(subprocess.TimeoutExpired):
            m.run_cli(['x'], popen=Slow)


class Protocol(Fixture):
    def test_initialize_list_and_call_over_stdio(self):
        lines = [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}},
                 {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                 {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
                 {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'drop_doctor', 'arguments': {}}},
                 {'jsonrpc': '2.0', 'id': 4, 'method': 'bogus'}]
        out = io.StringIO()
        m.serve(self.server(), io.StringIO(''.join(json.dumps(l) + '\n' for l in lines)), out)
        replies = [json.loads(l) for l in out.getvalue().splitlines()]
        self.assertEqual([r['id'] for r in replies], [1, 2, 3, 4])
        self.assertIn('untrusted', replies[0]['result']['instructions'])
        self.assertEqual({t['name'] for t in replies[1]['result']['tools']}, {'drop_doctor', 'drop_run', 'drop_receipt'})
        self.assertEqual(replies[3]['error']['code'], -32601)


class RealCli(unittest.TestCase):
    def test_real_doctor(self):
        out = json.loads(m.DropServer().call('drop_doctor', {})['content'][0]['text'])
        self.assertTrue(out['ok'])
        self.assertEqual(out['mode'], 'offline_files_only')


if __name__ == '__main__':
    unittest.main()
