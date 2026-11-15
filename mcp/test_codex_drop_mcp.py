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
