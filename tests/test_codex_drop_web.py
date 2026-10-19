#!/usr/bin/env python3
"""Socket-free adapter checks. No native Codex, SSH, browser, or model calls."""
import base64
import email.message
import hashlib
import http.server
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def forbidden(*args, **kwargs):
    raise AssertionError('A source-phase test attempted to create a socket/listener')


# Installed before adapter import; stay in force through every test, including Node harnesses.
GUARDS = [patch.object(socket, 'socket', forbidden), patch.object(socket, 'create_connection', forbidden),
          patch.object(socketserver.TCPServer, 'server_bind', forbidden),
          patch.object(socketserver.TCPServer, 'server_activate', forbidden)]
for guard in GUARDS:
    guard.start()
loader = importlib.machinery.SourceFileLoader('codex_drop_web', str(ROOT / 'bin/codex-drop-web'))
spec = importlib.util.spec_from_loader(loader.name, loader)
web = importlib.util.module_from_spec(spec)
loader.exec_module(web)


def image(name='screen.png', raw=b'\x89PNG\r\n\x1a\nfixture'):
    return {'name': name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'data': base64.b64encode(raw).decode()}


class FakeReceiver:
    def __init__(self):
        self.calls = []
        self.tui = 1
        self.composer = 'ready'
        self.upload_result = {'ok': True, 'status': 'transferred+attached-verified',
                              'files': [{'name': 'screen.png', 'size': 15,
                                         'attach': 'attached-verified'}],
                              'attach': {'state': 'verified', 'message': 'Review draft'}}
        self.upload_hook = None
        self.catalog_result = None

    def __call__(self, request):
        self.calls.append(request)
        if request['op'] == 'presence':
            return {'ok': True, 'tmux_ok': True, 'complete': True, 'truncated': False,
                    'threads': [web.THREAD], 'chats': [], 'process_complete': True,
                    'codex_present': False, **(self.catalog_result or {})}
        if request['op'] == 'catalog':
            if self.catalog_result is not None:
                return self.catalog_result
            target = self({'op': 'target', 'thread': web.THREAD})
            return {'ok': True, 'op': 'catalog', 'tmux_ok': True, 'complete': True,
                    'truncated': False, 'threads': [web.THREAD],
                    'chats': [{'target': target['target'], 'composer': target['composer']}]}
        if request['op'] == 'target':
            return {'ok': True, 'op': 'target', 'composer': self.composer,
                    'target_token': 'server-only-' + str(self.tui),
                    'target': {'thread': request.get('thread', web.THREAD), 'socket': 'default', 'pane': '%1',
                               'pane_pid': '2', 'window': '@1', 'tui_pid': str(self.tui),
                               'tui_start': '3', 'session': 'fixture', 'window_name': 'fixture'}}
        if self.upload_hook:
            return self.upload_hook(request)
        return self.upload_result


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.receiver = FakeReceiver()
        self.clock = [1.0]
        self.app = web.App('home.example.ts.net:9443', 'operator@example.test',
                           Path(self.tmp.name) / 'state', b'<html>fixture</html>',
                           self.receiver, clock=lambda: self.clock[0])
        self.nonce = self.call('/api/session', {})['nonce']

    def tearDown(self):
        self.app.close()
        self.tmp.cleanup()

    def headers(self, raw=None):
        h = email.message.Message()
        for k, v in {'Host': self.app.host, 'Tailscale-User-Login': self.app.login,
                     'Origin': self.app.origin, 'Content-Type': 'application/json',
                     'X-Codex-Drop-Nonce': getattr(self, 'nonce', '')}.items():
            h[k] = v
        if raw is not None:
            h['Content-Length'] = str(len(raw))
        return h

    def call(self, path, body=None, method='POST', headers=None, raw=None, stream=None, peer='127.0.0.1'):
        raw = web.canonical(body) if raw is None and method == 'POST' else raw
        headers = self.headers(raw) if headers is None else headers
        out = web.dispatch(self.app, method, path, headers, stream or io.BytesIO(raw or b''), peer)
        return json.loads(out) if path != '/' else out

    def confirmed(self):
        t = self.call('/api/target', {})
        self.assertNotIn('target_token', t)
        self.call('/api/confirm', {'target_id': t['target_id']})
        return t

    def payload(self):
        ticket = self.call('/api/operations', {'protocol': 2})
        return {'protocol': 2, 'operation_id': ticket['operation_id'], 'images': [image()]}

    def assert_refused(self, code, callback):
        with self.assertRaises(web.Refusal) as caught:
            callback()
        self.assertEqual(code, caught.exception.code)

    def test_socket_guards_are_live(self):
        self.assertRaises(AssertionError, socket.socket)
        self.assertRaises(AssertionError, socket.create_connection, ('localhost', 1))

    def test_page_get_identity_and_no_origin_required(self):
        h = self.headers()
        del h['Origin']
        self.assertIn(b'fixture', self.call('/', method='GET', headers=h))

    def test_identity_host_origin_and_duplicate_matrix(self):
        for field, bad, code in [('Host', 'evil.example:9443', 'identity'),
                                 ('Tailscale-User-Login', 'shared@example.test', 'identity'),
                                 ('Tailscale-User-Login', '', 'identity'),
                                 ('Origin', 'http://' + self.app.host, 'origin')]:
            h = self.headers(b'{}');h.replace_header(field, bad)
            self.assert_refused(code, lambda: self.call('/api/session', {}, headers=h))
        for field in ('Host', 'Tailscale-User-Login', 'Origin', 'Content-Length',
                      'Content-Type', 'X-Codex-Drop-Nonce'):
            h = self.headers(b'{}');h[field] = h[field]
            self.assert_refused('headers', lambda: self.call('/api/target', {}, headers=h))
        self.assert_refused('peer', lambda: self.call('/api/session', {}, peer='100.64.0.2'))

    def test_missing_identity_and_nonce(self):
        for field in ('Tailscale-User-Login', 'Origin'):
            h = self.headers(b'{}');del h[field]
            self.assert_refused('headers', lambda: self.call('/api/session', {}, headers=h))
        h = self.headers(b'{}');h.replace_header('X-Codex-Drop-Nonce', 'forged')
        self.assert_refused('session', lambda: self.call('/api/target', {}, headers=h))
        self.clock[0] += web.SESSION_TTL
        self.assert_refused('session', lambda: self.call('/api/target', {}))

    def test_confirmation_and_server_pinned_target(self):
        self.assert_refused('target_confirmation', lambda: self.call('/api/upload', self.payload()))
        for field in ('thread', 'socket', 'target_token', 'command', 'attach'):
            self.assert_refused('fields', lambda: self.call('/api/target', {field: 'foreign'}))
        self.confirmed();self.call('/api/upload', self.payload())
        req = self.receiver.calls[-1]
        self.assertEqual(req['thread'], web.THREAD)
        self.assertEqual(req['socket'], 'default')
        self.assertEqual(req['target_token'], 'server-only-1')
        self.assertTrue(req['attach'])

    def test_target_drift_invalidates_confirmation(self):
        self.confirmed();payload = self.payload();self.receiver.tui += 1
        self.assert_refused('target_changed', lambda: self.call('/api/upload', payload))
        self.assertFalse(self.app.session(self.nonce)['confirmed'])
        self.assertEqual([], [r for r in self.receiver.calls if r['op'] == 'upload'])

    def test_not_ready_and_foreign_thread_are_refused(self):
        t = self.call('/api/target', {});self.receiver.composer = 'not ready: busy'
        self.assert_refused('target_changed', lambda: self.call('/api/confirm', {'target_id': t['target_id']}))
        original = self.receiver
        def foreign(req):
            result = original(req)
            if req['op'] == 'target': result['target']['thread'] = str(uuid.uuid4())
            return result
        self.app.receiver = foreign
        self.assert_refused('target_unavailable', lambda: self.call('/api/target', {}))

    def test_upload_replay_conflict_and_recent_receipts(self):
        self.confirmed();payload = self.payload();first = self.call('/api/upload', payload)
        self.assertEqual(first, self.call('/api/upload', payload))
        self.assertEqual(1, len([r for r in self.receiver.calls if r['op'] == 'upload']))
        payload['images'] = [image('different.png')]
        self.assert_refused('operation_conflict', lambda: self.call('/api/upload', payload))
        receipt = self.call('/api/receipt/' + payload['operation_id'], method='GET')
        self.assertEqual(first['operation'], receipt['operation'])
        self.assertIsNone(receipt['resolution'])
        self.assertEqual(receipt['operation'], self.call('/api/receipts', method='GET')['operations'][0])

    def test_timeout_durable_reservation_never_reexecutes_after_restart(self):
        self.confirmed();payload = self.payload()
        def lost(req):
            record = self.app.journal.get(payload['operation_id'])
            self.assertEqual('uncertain', record[1]['state'])  # Durable BEFORE receiver invocation.
            raise TimeoutError()
        self.receiver.upload_hook = lost
        first = self.call('/api/upload', payload)
        self.assertEqual('uncertain', first['operation']['state'])
        self.app.close()
        self.app = web.App('home.example.ts.net:9443', 'operator@example.test',
                           Path(self.tmp.name) / 'state', receiver=self.receiver)
        self.nonce = self.call('/api/session', {})['nonce']
        self.assertEqual(first, self.call('/api/upload', payload))
        self.assertEqual(1, len([r for r in self.receiver.calls if r['op'] == 'upload']))

    def test_journal_does_not_store_image_data_or_nonce(self):
        self.confirmed();p = self.payload();self.call('/api/upload', p)
        raw = (Path(self.tmp.name) / 'state/receipts.sqlite3').read_bytes()
        self.assertNotIn(self.nonce.encode(), raw)
        self.assertNotIn(p['images'][0]['data'].encode(), raw)
        self.assertEqual(0o600, os.stat(Path(self.tmp.name) / 'state/receipts.sqlite3').st_mode & 0o777)

    def test_partial_receiver_result_is_preserved(self):
        self.confirmed();self.receiver.upload_result = {'ok': True, 'status': 'transferred',
            'files': [{'attach': 'attached-verified'}, {'attach': 'paste-uncertain'},
                      {'attach': 'not-attempted'}], 'attach': {'state': 'blocked'}}
        result = self.call('/api/upload', self.payload())['operation']['result']
        self.assertEqual(result, self.receiver.upload_result)
        self.assertEqual('blocked', result['attach']['state'])

    def test_concurrent_pages_do_not_dispatch_twice(self):
        self.confirmed();started, finish = threading.Event(), threading.Event()
        def held(req):
            started.set();self.assertTrue(finish.wait(2));return self.receiver.upload_result
        self.receiver.upload_hook = held
        payload = self.payload();out = []
        worker = threading.Thread(target=lambda: out.append(self.call('/api/upload', payload)))
        worker.start();self.assertTrue(started.wait(2))
        try:
            self.assertEqual('uncertain', self.call('/api/upload', payload)['operation']['state'])
            self.assert_refused('busy', lambda: self.call('/api/upload', self.payload()))
        finally:
            finish.set();worker.join(3)
        self.assertFalse(worker.is_alive());self.assertEqual(1, len(out))
        self.assertEqual(1, len([r for r in self.receiver.calls if r['op'] == 'upload']))

    def test_body_bounds_encoding_interruption_and_duplicate_json(self):
        h = self.headers(b'{}');h.replace_header('Content-Length', str(web.MAX_BODY + 1))
        class NoRead:
            def read(self, _): raise AssertionError('Oversize body was read')
        self.assert_refused('body_size', lambda: self.call('/api/session', {}, headers=h, stream=NoRead()))
        for header in ('Transfer-Encoding', 'Content-Encoding'):
            h = self.headers(b'{}');h[header] = 'chunked'
            self.assert_refused('encoding', lambda: self.call('/api/session', {}, headers=h))
        self.assert_refused('body', lambda: self.call('/api/session', {}, stream=io.BytesIO(b'{')))
        self.assert_refused('json', lambda: self.call('/api/session', raw=b'{"x":1,"x":2}'))
        class TimedOut:
            def read(self, _): raise TimeoutError()
        self.assert_refused('read_timeout', lambda: self.call('/api/session', {}, stream=TimedOut()))
        self.assert_refused('request', lambda: self.call('/api/session', {}, method='OPTIONS'))

    def test_image_validation_hash_formats_and_declared_limits(self):
        for raw in (b'<svg>bad</svg>', b'notheic', b'<html>x</html>'):
            self.assert_refused('format', lambda: web.validate_images([image(raw=raw)]))
        bad = image();bad['sha256'] = '0' * 64
        self.assert_refused('digest', lambda: web.validate_images([bad]))
        bad = image();bad['size'] = web.MAX_IMAGE + 1
        self.assert_refused('size', lambda: web.validate_images([bad]))
        self.assert_refused('images', lambda: web.validate_images([image()] * 11))
        for raw in (b'\xff\xd8\xffxx', b'GIF89axx', b'RIFF1234WEBPxx'):
            web.validate_images([image(raw=raw)])
        with patch.object(web, 'MAX_BATCH', 1):
            self.assert_refused('size', lambda: web.validate_images([image()]))

    def test_full_50mib_batch_fits_http_and_receiver_frame(self):
        raw = b'\x89PNG\r\n\x1a\n' + b'x' * (web.MAX_IMAGE - 8)
        item = image(raw=raw)
        images = [item, item]
        web.validate_images(images)
        body = {'operation_id': str(uuid.uuid4()), 'images': images}
        self.assertLess(len(web.canonical(body)), web.MAX_BODY)
        receiver = {'version': 1, 'op': 'upload', 'thread': web.THREAD, 'socket': 'default',
                    'target_token': 'x' * 4096, 'images': images, 'attach': True}
        self.assertLess(len(web.canonical(receiver)), web.MAX_FRAME)

    def test_actual_http_response_privacy_and_csp_headers(self):
        from types import SimpleNamespace
        page = (ROOT / 'share/codex-drop-web/index.html').read_bytes()
        h = object.__new__(web.Handler)
        h.wfile = io.BytesIO()
        h.requestline, h.request_version, h.command = 'GET / HTTP/1.0', 'HTTP/1.0', 'GET'
        h.server = SimpleNamespace(page_csp=web.csp(page))
        h.respond(200, page, html=True)
        raw_headers, body = h.wfile.getvalue().split(b'\r\n\r\n', 1)
        parsed = email.message_from_bytes(raw_headers.split(b'\r\n', 1)[1])
        self.assertEqual(page, body)
        self.assertEqual(str(len(page)), parsed['Content-Length'])
        self.assertEqual('same-origin', parsed['Referrer-Policy'])
        self.assertEqual('no-store', parsed['Cache-Control'])
        self.assertEqual(web.csp(page), parsed['Content-Security-Policy'])
        self.assertIsNone(parsed['Set-Cookie'])
        self.assertIsNone(parsed['Access-Control-Allow-Origin'])

    def test_resource_caps_and_single_instance(self):
        self.assert_refused('instance', lambda: web.Journal(Path(self.tmp.name) / 'state'))
        with patch.object(web, 'MAX_SESSIONS', 1):
            self.assert_refused('sessions', lambda: self.call('/api/session', {}))
        self.confirmed()
        with patch.object(web, 'MAX_UNRESOLVED', 0):
            self.assert_refused('journal_full', lambda: self.call('/api/upload', self.payload()))
        self.assertFalse(any(r['op'] == 'upload' for r in self.receiver.calls))

    def test_unsafe_state_and_private_config(self):
        p = Path(self.tmp.name) / 'unsafe';p.mkdir(mode=0o755)
        self.assert_refused('state', lambda: web.Journal(p))
        link = Path(self.tmp.name) / 'link';link.symlink_to(Path(self.tmp.name) / 'state')
        self.assertRaises(OSError, web.Journal, link)
        config = Path(self.tmp.name) / 'config';config.write_bytes(b'{}');config.chmod(0o644)
        self.assert_refused('config', lambda: web.load_config(config))
        config.chmod(0o600)
        config.write_bytes(web.canonical({'canonical_host': self.app.host, 'allowed_login': self.app.login}))
        self.assertEqual(self.app.host, web.load_config(config)['canonical_host'])


class PipeProcess:
    """Fake subprocess using anonymous pipes, with no process, socket or listener."""
    def __init__(self, output=b'{}\n', hang=False):
        in_read, in_write = os.pipe();out_read, out_write = os.pipe();err_read, err_write = os.pipe()
        self.stdin = os.fdopen(in_write, 'wb', buffering=0)
        self.stdout = os.fdopen(out_read, 'rb', buffering=0)
        self.stderr = os.fdopen(err_read, 'rb', buffering=0)
        self.done = threading.Event();self.killed = False;self.received = bytearray()
        def worker():
            try:
                while True:
                    chunk = os.read(in_read, 65536)
                    if not chunk: break
                    self.received.extend(chunk)
                view = memoryview(output)
                while view:
                    view = view[os.write(out_write, view):]
                if hang: self.done.wait(2)
            except OSError:
                pass
            finally:
                for fd in (in_read, out_write, err_write):
                    os.close(fd)
                self.done.set()
        self.worker = threading.Thread(target=worker);self.worker.start()

    def poll(self): return 0 if self.done.is_set() else None
    def wait(self, timeout=None):
        if not self.done.wait(timeout): raise subprocess.TimeoutExpired('fake', timeout)
        return 0
    def kill(self): self.killed = True;self.done.set()
    def join(self): self.worker.join(3)


class NamespaceOwnershipTests(unittest.TestCase):
    IDENTITY_MAP = ((0, 0, 4294967295),)
    PRIVATE_MAP = ((1000, 1000, 1),)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name)
        self.state = self.parent / 'state'
        self.state.mkdir(mode=0o700)
        self.real_fstat = os.fstat
        self.parent_key = self.key(self.parent.stat())
        self.final_key = self.key(self.state.stat())
        self.home_key = self.key(Path('/home').stat())

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def key(info):
        return info.st_dev, info.st_ino

    def altered_stats(self, changes):
        def observe(fd):
            info = self.real_fstat(fd)
            change = changes.get(self.key(info))
            if change is None:
                return info
            values = list(info)
            if 'uid' in change:
                values[stat.ST_UID] = change['uid']
            if 'mode' in change:
                values[stat.ST_MODE] = stat.S_IFDIR | change['mode']
            return os.stat_result(values)
        return observe

    def gate(self, changes=None, mapping=IDENTITY_MAP):
        with patch.object(web, 'read_uid_map', return_value=mapping), \
             patch.object(web, 'read_overflow_uid', return_value=65534), \
             patch.object(web.os, 'fstat', self.altered_stats(changes or {})), \
             patch.object(web.os, 'mkdir', side_effect=AssertionError('Gate wrote')), \
             patch.object(web, 'private_file', side_effect=AssertionError('Gate wrote')):
            return web.check_ancestors(self.state)

    def app_directory(self, changes=None, mapping=IDENTITY_MAP, invocation=None):
        environment = {} if invocation is None else {'INVOCATION_ID': invocation}
        with patch.object(web, 'read_uid_map', return_value=mapping), \
             patch.object(web, 'read_overflow_uid', return_value=65534), \
             patch.dict(os.environ, environment, clear=True), \
             patch.object(web.os, 'fstat', self.altered_stats(changes or {})):
            fd = web.private_directory(self.state)
            os.close(fd)

    def test_gate_identity_view_is_read_only(self):
        before = sorted(p.name for p in self.parent.iterdir())
        self.assertIsNone(self.gate())
        self.assertEqual(before, sorted(p.name for p in self.parent.iterdir()))
        self.assertEqual([], list(self.state.iterdir()))

    def test_gate_rejects_nonidentity_view_before_walking(self):
        with patch.object(web.os, 'open', side_effect=AssertionError('Walked before map check')):
            self.assertRaises(web.Refusal, self.gate, mapping=self.PRIVATE_MAP)
        self.assertRaises(web.Refusal, self.gate, {self.home_key: {'uid': 65534}})

    def test_gate_unsafe_ancestors_and_real_root_sticky_policy(self):
        for change in ({'uid': 2000}, {'mode': 0o775}, {'mode': 0o757}):
            with self.subTest(change=change):
                self.assertRaises(web.Refusal, self.gate, {self.parent_key: change})
        self.gate({self.parent_key: {'uid': 0, 'mode': 0o1777}})
        self.assertRaises(web.Refusal, self.gate,
                          {self.parent_key: {'uid': 2000, 'mode': 0o1777}})

    def test_gate_refuses_symlink_and_final_owner_or_mode(self):
        for change in ({'uid': 2000}, {'mode': 0o750}, {'mode': 0o4700}):
            with self.subTest(change=change):
                self.assertRaises(web.Refusal, self.gate, {self.final_key: change})
        link = self.parent / 'redirect'
        link.symlink_to(self.state, target_is_directory=True)
        with patch.object(web, 'read_uid_map', return_value=self.IDENTITY_MAP), \
             patch.object(web, 'read_overflow_uid', return_value=65534):
            self.assertRaises(OSError, web.check_ancestors, link)
            parent_link = self.parent / 'parent-link'
            parent_link.symlink_to(self.parent, target_is_directory=True)
            self.assertRaises(OSError, web.check_ancestors, parent_link / 'state')
        self.assertEqual([], list(self.state.iterdir()))

    def test_sandbox_overflow_ancestor_requires_all_conditions(self):
        overflow = {self.parent_key: {'uid': 65534, 'mode': 0o755}}
        self.app_directory(overflow, self.PRIVATE_MAP, 'fixture-invocation')
        for mapping, invocation in ((self.PRIVATE_MAP, None),
                                    (self.PRIVATE_MAP, ''),
                                    (self.IDENTITY_MAP, 'fixture-invocation'),
                                    (((0, 0, 1), (1000, 1000, 1)), 'fixture-invocation'),
                                    (((1000, 0, 1),), 'fixture-invocation')):
            with self.subTest(mapping=mapping, invocation=invocation):
                self.assertRaises(web.Refusal, self.app_directory,
                                  overflow, mapping, invocation)

    def test_overflow_has_no_writable_sticky_or_final_exception(self):
        for mode in (0o775, 0o757, 0o1777):
            with self.subTest(mode=mode):
                self.assertRaises(web.Refusal, self.app_directory,
                                  {self.parent_key: {'uid': 65534, 'mode': mode}},
                                  self.PRIVATE_MAP, 'fixture-invocation')
        self.assertRaises(web.Refusal, self.app_directory,
                          {self.final_key: {'uid': 65534}},
                          self.PRIVATE_MAP, 'fixture-invocation')

    def test_mapped_foreign_owner_is_never_overflow_exception(self):
        mapping = ((1000, 1000, 1), (65534, 2000, 1))
        self.assertRaises(web.Refusal, self.app_directory,
                          {self.parent_key: {'uid': 65534}}, mapping, 'fixture-invocation')
        self.assertRaises(web.Refusal, self.app_directory,
                          {self.parent_key: {'uid': 2000}},
                          self.PRIVATE_MAP, 'fixture-invocation')

    def test_strict_default_still_accepts_and_rejects_original_cases(self):
        self.app_directory()
        self.app_directory({self.parent_key: {'uid': 0, 'mode': 0o1777}})
        self.assertRaises(web.Refusal, self.app_directory,
                          {self.parent_key: {'uid': 2000}})
        self.assertRaises(web.Refusal, self.app_directory,
                          {self.final_key: {'mode': 0o750}})

    def test_uid_map_and_overflow_parsing_fail_closed(self):
        with patch.object(web, '_read_proc_text', return_value='0 0 4294967295\n'):
            self.assertEqual(self.IDENTITY_MAP, web.read_uid_map())
        for raw in ('', '0 0 0', '-1 0 1', '0 0 4294967296', '0 0 1 extra',
                    '0 0 2\n1 3 1', '0 0 2\n3 1 1', '0 0 ' + '9' * 5000):
            with self.subTest(raw=raw), patch.object(web, '_read_proc_text', return_value=raw):
                self.assertRaises(web.Refusal, web.read_uid_map)
        with patch.object(web, '_read_proc_text', return_value='65534\n'):
            self.assertEqual(65534, web.read_overflow_uid())
        for raw in ('', '-1', '4294967295', '65534 1', '9' * 5000):
            with self.subTest(raw=raw), patch.object(web, '_read_proc_text', return_value=raw):
                self.assertRaises(web.Refusal, web.read_overflow_uid)

    def test_check_mode_never_constructs_app_or_server(self):
        with patch.object(sys, 'argv', ['codex-drop-web', '--check-ancestors',
                                       '--config', '/fixture/config.json']), \
             patch.object(web, 'check_ancestors') as gate, \
             patch.object(web, 'App', side_effect=AssertionError('Gate constructed app')), \
             patch.object(web, 'Server', side_effect=AssertionError('Gate constructed server')):
            web.main()
        gate.assert_called_once_with(web.state_path(), config_path='/fixture/config.json')

    def test_only_one_prestart_command_bypasses_namespace(self):
        unit = (ROOT / 'services/codex-drop-web.service').read_text()
        bypass = [line for line in unit.splitlines() if re.match(r'Exec\w+=\+', line)]
        self.assertEqual(['ExecStartPre=+/usr/bin/python3 -I %h/.local/bin/codex-drop-web '
                          '--check-ancestors --config %h/.config/codex-drop-web/config.json'], bypass)
        self.assertEqual(1, sum(line.startswith('ExecStartPre=') for line in unit.splitlines()))
        for line in ('ProtectHome=read-only', 'ProtectSystem=strict', 'Restart=on-failure',
                     'RestartSec=5', 'StartLimitIntervalSec=300', 'StartLimitBurst=3'):
            self.assertIn(line, unit.splitlines())
        self.assertFalse(any(line.startswith('PrivateUsers=') for line in unit.splitlines()))


class ReceiverBoundaryTests(unittest.TestCase):
    def test_streaming_io_and_deadline_and_overflow(self):
        p = PipeProcess(output=b'{"ok":true}\n')
        try:
            self.assertEqual(b'{"ok":true}\n', web.pump_process(p, b'x' * 200000, 2, kill=p.kill))
            self.assertEqual(200000, len(p.received))
        finally: p.join()
        for output, hang, code in ((b'x' * 8192, False, 'receiver_output'),
                                   (b'', True, 'receiver_timeout')):
            p = PipeProcess(output=output, hang=hang)
            try:
                with self.assertRaises(web.Refusal) as caught:
                    web.pump_process(p, b'{}', 0.05, limit=100, kill=p.kill)
                self.assertEqual(code, caught.exception.code);self.assertTrue(p.killed)
            finally: p.join()

    def test_fixed_command_framing_and_reply_validation(self):
        made = []
        def popen(*args, **kwargs):
            self.assertEqual(['python3', '-I', web.RECEIVER, 'receive'], args[0])
            self.assertFalse(kwargs['shell']);self.assertTrue(kwargs['start_new_session'])
            self.assertEqual('/usr/bin:/bin', kwargs['env']['PATH'])
            p = PipeProcess(output=b'{"ok":true}\n');made.append(p);return p
        with patch.object(web.subprocess, 'Popen', popen):
            self.assertTrue(web.Receiver()({'op': 'target'})['ok'])
        made[0].join();payload = bytes(made[0].received)
        self.assertEqual(len(payload) - 4, int.from_bytes(payload[:4], 'big'))
        self.assertEqual({'op': 'target'}, json.loads(payload[4:]))


class FrontendTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / 'share/codex-drop-web/index.html'
        if not self.path.exists(): self.skipTest('Frontend baton has not returned; backend-only milestone')

    def test_csp_and_static_privacy(self):
        page = self.path.read_bytes();policy = web.csp(page)
        self.assertNotIn('unsafe-inline', policy)
        self.assertNotRegex(page.decode(), r'https?://|localStorage|sessionStorage|document\.cookie')
        for tag in ('script', 'style'):
            for block in re.findall(r'<' + tag + r'(?:\s[^>]*)?>(.*?)</' + tag + '>', page.decode(), re.S):
                digest = base64.b64encode(hashlib.sha256(block.encode()).digest()).decode()
                self.assertIn("'sha256-" + digest + "'", policy)

    def test_node_ui_harness(self):
        import shutil
        node = shutil.which('node')
        if not node: self.skipTest('Node is unavailable; static frontend checks still run')
        # The frontend baton must expose a pure helper object before optional DOM bootstrap.
        script = re.search(r'<script>(.*?)</script>', self.path.read_text(), re.S).group(1)
        harness = '''
globalThis.CODEX_DROP_TEST = true;
'''+script+'''
const assert = require('node:assert/strict');
const h = globalThis.CodexDropTest;
assert.ok(h, 'Missing fixed offline UI hook');
assert.equal(h.allowedFile({name:'x.png',type:'image/png',size:5}),true);
assert.equal(h.allowedFile({name:'x.heic',type:'image/heic',size:5}),false);
assert.equal(h.verified({state:'completed',result:{ok:true,attach:{state:'verified'},files:[{attach:'attached-verified'}]}}),true);
for (const state of ['blocked','unverified','skipped','pasting','anything'])
 assert.equal(h.verified({state:'completed',result:{ok:true,attach:{state},files:[{attach:'not-attempted'}]}}),false);
const s=h.createState();h.confirm(s);assert.equal(s.armed,true);
const id='11111111-1111-4111-8111-111111111111';h.begin(s,id);h.fail(s);
assert.equal(s.armed,false);assert.equal(s.operationId,id);
assert.equal(h.mayAutoUpload(s),false);
assert.equal(h.allowRetry(s,false,false),false);assert.equal(s.armed,false);
assert.equal(h.allowRetry(s,true,true),true);assert.equal(s.operationId,null);
assert.equal(s.armed,true);
console.log('offline UI logic PASS');
'''
        result = subprocess.run([node, '--no-addons', '-e', harness], capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('offline UI logic PASS', result.stdout)

    def run_node(self, harness, dom=False):
        import shutil
        node = shutil.which('node')
        if not node: self.skipTest('Node is unavailable')
        script = re.search(r'<script>(.*?)</script>', self.path.read_text(), re.S).group(1)
        prefix = "const assert=require('node:assert/strict');\n"
        if dom:
            source = prefix + 'const pageScript=' + json.dumps(script) + ';\n' + harness
        else:
            source = prefix + 'globalThis.CODEX_DROP_TEST=true;\n' + script + '\n' + harness
        result = subprocess.run([node, '--no-addons', '-e', source], capture_output=True, text=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_controller_lifecycle_and_recovery(self):
        self.run_node(r'''
const h=globalThis.CodexDropTest;
const file={name:'screen.png',type:'image/png',size:12};
const uncertain=id=>({operation_id:id,state:'uncertain',result:{ok:false,error:{code:'outcome_uncertain'}}});
const verified=(id,images)=>({operation_id:id,state:'completed',result:{ok:true,
 attach:{state:'verified'},files:images.map(x=>({name:x.name,attach:'attached-verified'}))}});
function fixture(options={}) {
 const calls=[];let count=0, mode=options.mode||'verified', inspected=0;
 const recent=(options.recent||[]).map(x=>({...x}));
 const api=async(method,path,body,nonce)=>{
   calls.push({method,path,body,nonce});
   if(path==='/api/session')return {ok:true,nonce:'memory-only',protocol:2,ttl_seconds:900,retention_days:7,thread:'home',limits:{max_files:10,max_image:26214400,max_batch:52428800}};
   assert.equal(nonce,'memory-only');
   if(path==='/api/receipts')return {ok:true,operations:recent};
   if(path==='/api/chats')return {ok:true,chats:[{selection_id:'opaque',target:{thread:'home'},composer:'ready',is_default:true}]};
   if(path==='/api/operations'){
     if(options.ticketError)throw Error('Ticket connection failed');
     return {ok:true,operation_id:options.ticketId||`11111111-1111-4111-8111-${String(++count).padStart(12,'0')}`};
   }
   if(path==='/api/resolve'){
     const resolution={state:'acknowledged',at:'fixture'};
     const op=recent.find(x=>x.operation_id===body.operation_id);if(op)op.resolution=resolution;
     return {ok:true,resolution};
   }
   if(path==='/api/target')return {ok:true,target_id:'target-ref',target:{thread:'home'},composer:'ready'};
   if(path==='/api/confirm')return {ok:true,confirmed:true,target:{thread:'home'}};
   if(path.startsWith('/api/receipt/')){
     inspected++;
     if(mode==='receipt-network')throw Error('offline');
     if(mode==='wrong-404')return {ok:false,http_status:404,error:{code:'route'}};
     if(mode==='missing')return {ok:false,http_status:404,error:{code:'receipt_missing'}};
     return {ok:true,operation:uncertain(path.split('/').pop())};
   }
   if(path==='/api/upload'){
     assert.equal(c.state.operationId,body.operation_id); // ID assigned before network call.
     if(mode==='network')throw Error('lost after dispatch');
     if(mode==='http')return {ok:false,http_status:503,error:{code:'service_unavailable'}};
     if(mode==='blocked')return {ok:true,operation:{operation_id:body.operation_id,state:'completed',result:{ok:true,attach:{state:'blocked'},files:[{attach:'paste-uncertain'}]}}};
     return {ok:true,operation:verified(body.operation_id,body.images)};
   }
   throw Error('Unexpected endpoint '+path);
 };
 const c=h.createController({api,
 prepare:options.prepare|| (async files=>files.map(f=>({name:f.name,size:f.size}))) });
 return {c,calls,mode:m=>mode=m,uploads:()=>calls.filter(x=>x.path==='/api/upload'),inspected:()=>inspected};
}
(async()=>{
 let f=fixture();await f.c.connect();
 await f.c.addFiles([file]);assert.equal(f.uploads().length,0);
 await f.c.confirmChat();await f.c.send();assert.equal(f.uploads().length,1);
 assert.equal(f.c.state.queue.length,0);assert.equal(f.c.state.armed,true);
 await f.c.addFiles([file]);assert.equal(f.uploads().length,2); // Real drop/picker method auto-attaches.
 for(const mode of ['network','http','blocked']) {
   f=fixture({mode});await f.c.connect();await f.c.confirmChat();await f.c.addFiles([file]);
   const old=f.c.state.operationId;assert.ok(old);assert.equal(f.c.state.armed,false);
   assert.equal(f.c.state.queue.length,1);assert.equal(await f.c.retry(false),false);
   await f.c.addFiles([file]);assert.equal(f.uploads().length,1);assert.equal(f.c.state.queue.length,2);
   assert.equal(await f.c.send(),false);assert.equal(f.uploads().length,1);
   f.mode('receipt-network');assert.equal(await f.c.inspect(),false);assert.equal(await f.c.retry(true),false);
   f.mode('wrong-404');assert.equal(await f.c.inspect(),false);assert.equal(await f.c.retry(true),false);
   f.mode('missing');assert.equal(await f.c.inspect(),true);assert.equal(await f.c.retry(false),false);
   assert.equal(await f.c.retry(true),true);assert.equal(f.uploads().length,1); // Retry permission is not dispatch.
   f.mode('verified');await f.c.send();assert.equal(f.uploads().length,2);
   assert.notEqual(f.uploads()[1].body.operation_id,old);assert.equal(f.c.state.queue.length,0);
 }
 f=fixture({recent:[uncertain('old')]});await f.c.connect();await f.c.confirmChat();
 await f.c.addFiles([file]);assert.equal(f.uploads().length,0);assert.equal(f.c.state.armed,false);
 await f.c.inspect();assert.equal(await f.c.retry(true),true);assert.equal(f.uploads().length,0);
 f=fixture({prepare:async()=>{throw Error('file read interrupted')}});
 await f.c.connect();await f.c.confirmChat();await f.c.addFiles([file]);
 assert.equal(f.uploads().length,0);assert.equal(f.c.state.queue.length,1);assert.equal(f.c.state.operationId,null);
 assert.equal(f.calls.filter(x=>x.path==='/api/operations').length,0);
 f=fixture();await f.c.connect();await f.c.confirmChat();
 assert.equal(await f.c.addFiles([{...file,size:26214401}]),false);
 assert.equal(await f.c.addFiles([{...file,type:'image/heic',name:'screen.heic'}]),false);
 assert.equal(await f.c.addFiles(Array(11).fill(file)),false);assert.equal(f.uploads().length,0);
 assert.equal(h.validateBatch([],Array(2).fill({...file,size:26214400}),null).ok,true);
 assert.equal(h.validateBatch([],Array(3).fill({...file,size:26214400}),null).ok,false);
 for(const options of [{ticketId:'not-a-uuid'},{ticketError:true}]) {
   f=fixture(options);await f.c.connect();await f.c.confirmChat();await f.c.addFiles([file]);
   assert.equal(f.c.state.armed,false);assert.equal(f.c.state.queue.length,1);
   await f.c.addFiles([file]);assert.equal(f.uploads().length,0);
   assert.equal(f.c.state.error,null); // Adding valid files does not arm or dispatch them.
 }
 console.log('controller lifecycle/recovery PASS');
})().catch(e=>{console.error(e);process.exitCode=1});
''')

    def test_actual_dom_picker_drop_and_no_retry(self):
        self.run_node(r'''
const vm=require('node:vm');const crypto=require('node:crypto');
class Element {
 constructor(tag){this.tag=tag;this.children=[];this.events={};this._text='';this.disabled=false;this.checked=false;
   this.classList={add(){},remove(){},toggle(){}};this.clicks=0;}
 set textContent(s){this._text=String(s);this.children=[];}
 get textContent(){return this._text+this.children.map(x=>x.textContent).join('');}
 set innerHTML(_){throw Error('Untrusted HTML rendering');}
 appendChild(n){if(n.tag==='#fragment')this.children.push(...n.children);else this.children.push(n);return n;}
 replaceChildren(...ns){this.children=[];this._text='';ns.forEach(n=>this.appendChild(n));}
 setAttribute(k,v){this[k]=v;}
 focus(){document.activeElement=this;}
 addEventListener(k,v){(this.events[k]||=([])).push(v);}
 fire(k,e={}){for(const cb of this.events[k]||[])cb(e);}
 click(){this.clicks++;if(!this.disabled)this.fire('click');}
}
const nodes=new Map(),docEvents={},winEvents={};
const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Element(id));return nodes.get(id);},
 createElement:tag=>new Element(tag),createDocumentFragment:()=>new Element('#fragment'),
 addEventListener(k,cb){(docEvents[k]||=([])).push(cb);}};
const id=n=>document.getElementById(n);const calls=[],uploads=[],receipts=new Map(),revoked=[];
let lose=false,ticketCount=0,failRead=false,failSession=false,protocol=2;
const target={thread:'home',session:'fixture',window_name:'test'};
const fakeFetch=async(path,init)=>{
 calls.push(path);if(failSession&&path==='/api/session')throw Error('Fixture session failure');if(failRead&&path==='/api/receipts')return{ok:false,status:503,text:async()=>JSON.stringify({ok:false,error:{code:'receipts_failed',message:'Fixture refusal'}})};assert.equal(init.credentials,'omit');assert.equal(init.mode,'same-origin');
 assert.equal(init.referrerPolicy,'same-origin');assert.equal(init.redirect,'error');
 const body=init.body?JSON.parse(init.body):null;let data;
 if(path==='/api/session')data={ok:true,nonce:'memory-only',protocol,ttl_seconds:900,retention_days:7,thread:'home',limits:{max_files:10,max_image:26214400,max_batch:52428800}};
 else{
  assert.equal(init.headers['X-Codex-Drop-Nonce'],'memory-only');
  if(path==='/api/receipts')data={ok:true,operations:Array.from(receipts.values())};
  else if(path==='/api/chats')data={ok:true,chats:[{selection_id:'opaque',target,composer:'ready',is_default:true}]};
  else if(path==='/api/operations')data={ok:true,operation_id:`11111111-1111-4111-8111-${String(++ticketCount).padStart(12,'0')}`};
  else if(path==='/api/resolve'){
    const resolution={state:'acknowledged',at:'fixture'};
    receipts.get(body.operation_id).resolution=resolution;data={ok:true,resolution};
  }
  else if(path==='/api/target')data={ok:true,target_id:'reference',target,composer:'ready'};
  else if(path==='/api/confirm')data={ok:true,confirmed:true,target};
  else if(path.startsWith('/api/receipt/'))data={ok:true,operation:receipts.get(path.split('/').pop())};
  else if(path==='/api/upload'){
    uploads.push(body);assert.match(body.operation_id,/^[a-f0-9-]{36}$/);
    for(const image of body.images){const raw=Buffer.from(image.data,'base64');assert.equal(raw.length,image.size);
      assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),image.sha256);}
    const op={operation_id:body.operation_id,target,state:lose?'uncertain':'completed',result:lose?
      {ok:false,error:{code:'outcome_uncertain'}}:{ok:true,attach:{state:'verified'},
        files:body.images.map(x=>({...x,data:undefined,attach:'attached-verified'}))}};
    receipts.set(body.operation_id,op);if(lose)throw Error('Network lost after receiver dispatch');
    data={ok:true,operation:op};
  }else throw Error('Unexpected URL '+path);
 }
 return {ok:true,status:200,text:async()=>JSON.stringify(data)};
};
const errors=[];
const context=vm.createContext({document,window:{addEventListener(k,v){winEvents[k]=v;}},
 console:{log(){},error(e){errors.push(String(e));}},URL:{createObjectURL:()=> 'blob:fixture',revokeObjectURL:u=>revoked.push(u)},
 crypto:crypto.webcrypto,Uint8Array,AbortController,fetch:fakeFetch,btoa:s=>Buffer.from(s,'binary').toString('base64'),
 setTimeout:()=>1,clearTimeout(){}});
const until=async predicate=>{const end=Date.now()+3000;while(!predicate()&&Date.now()<end)await new Promise(r=>setTimeout(r,2));assert.ok(predicate(),'UI timed out');};
const file=name=>{const raw=Buffer.from('\x89PNG\r\n\x1a\nfixture','binary');return {name,type:'image/png',size:raw.length,
 arrayBuffer:async()=>raw.buffer.slice(raw.byteOffset,raw.byteOffset+raw.byteLength)};};
const drop=files=>{let prevented=false;const e={dataTransfer:{types:['Files'],files},preventDefault(){prevented=true;}};
 docEvents.drop.forEach(cb=>cb(e));assert.equal(prevented,true);};
(async()=>{
 vm.runInContext(pageScript,context);
 await until(()=>!id('use-chat').disabled);
 drop([file('focus-one.png'),file('focus-two.png')]);await until(()=>id('queue').children.length===2);
 const removeButton=i=>id('queue').children[i].children.find(n=>n.tag==='button');
 removeButton(0).focus();removeButton(0).click();
 assert.equal(document.activeElement,removeButton(0),'Remove should move focus to the next remaining file');
 removeButton(0).click();assert.equal(document.activeElement,id('choose'),'An empty queue returns focus to the chooser');
 assert.equal(uploads.length,0);id('use-chat').click();await until(()=>id('state').textContent.startsWith('Ready'));
 id('choose').click();assert.equal(id('picker').clicks,1);
 id('picker').files=[file('picker.png')];id('picker').fire('change');
 await until(()=>uploads.length===1&&id('queue').children.length===0);
 assert.ok(id('message').textContent.includes('Attached to Codex draft'));
 lose=true;const name='<img src=x onerror=bad>.png';drop([file(name)]);
 await until(()=>uploads.length===2&&!id('recovery').hidden);
 assert.ok(id('incidents').textContent.includes('Chat: test (fixture)'), 'Recovery must identify the affected chat');
 assert.ok(id('queue').textContent.includes(name));drop([file('more.png')]);
 await new Promise(r=>setTimeout(r,10));assert.equal(uploads.length,2);assert.equal(id('queue').children.length,2);
 for(const cb of docEvents.visibilitychange||[])cb({});assert.equal(uploads.length,2);
 id('inspect').click();await until(()=>!id('ack').disabled);id('ack').checked=true;id('ack').fire('change');
 assert.equal(id('allow-new').disabled,false);id('allow-new').click();assert.equal(uploads.length,2);
 await until(()=>id('message').textContent.includes('Marked as checked'));
 lose=false;id('attach').click();await until(()=>uploads.length===3&&id('queue').children.length===0);
 assert.notEqual(uploads[1].operation_id,uploads[2].operation_id);assert.ok(revoked.length>=3);
 failRead=true;context.testNow=Date.now()+10000;
 vm.runInContext('Date.now=function(){return testNow;};',context);winEvents.focus();
 await until(()=>id('state').textContent.startsWith('Not connected'));
 assert.equal(id('connect-row').hidden,false);assert.equal(id('attach').disabled,true);
 assert.equal(id('use-chat').disabled,true);assert.equal(id('refresh-target').disabled,true);
 assert.equal(id('chat-select').disabled,true);assert.equal(id('connect').textContent,'Reconnect');
 assert.match(id('message').textContent+' '+id('error').textContent,/reconnect|couldn't check/i);
 failRead=false;context.testNow+=10000;winEvents.focus();
 await until(()=>id('state').textContent.startsWith('Check the chat'));
 assert.equal(id('error').textContent,'','A successful later readiness check clears its earlier failure');
 failSession=true;context.testNow+=901000;winEvents.focus();
 await until(()=>id('state').textContent.startsWith('Not connected'));
 assert.equal(id('connect').textContent,'Reconnect','A failed renewal must offer the action named in its error');
 failSession=false;protocol=1;context.testNow+=10000;winEvents.focus();
 await until(()=>id('state').textContent.includes('out of date'));
 assert.equal(id('connect').disabled,true);assert.match(id('error').textContent,/out of date.*reload/i);
 assert.deepEqual(errors,[]);console.log('actual DOM picker/drop/recovery PASS');
})().catch(e=>{console.error(e);process.exitCode=1});
''', dom=True)


class V5BackendTests(unittest.TestCase):
    setUp = AdapterTests.setUp
    tearDown = AdapterTests.tearDown
    headers = AdapterTests.headers
    call = AdapterTests.call
    confirmed = AdapterTests.confirmed
    assert_refused = AdapterTests.assert_refused

    def payload(self):
        ticket = self.call('/api/operations', {'protocol': 2})
        return {'protocol': 2, 'operation_id': ticket['operation_id'], 'images': [image()]}

    def test_unknown_id_never_becomes_an_upload(self):
        self.confirmed()
        payload = {'protocol': 2, 'operation_id': str(uuid.uuid4()), 'images': [image()]}
        self.assert_refused('operation_unknown', lambda: self.call('/api/upload', payload))
        self.assertFalse(any(r['op'] == 'upload' for r in self.receiver.calls))

    def test_stale_protocol_is_refused_before_dispatch(self):
        self.confirmed()
        self.assert_refused('protocol_reload', lambda: self.call('/api/upload',
                            {'operation_id': str(uuid.uuid4()), 'images': [image()]}))
        self.assertFalse(any(r['op'] == 'upload' for r in self.receiver.calls))

    def test_ticket_is_session_bound_and_single_use(self):
        self.confirmed(); payload = self.payload()
        self.nonce = self.call('/api/session', {})['nonce']; self.confirmed()
        self.assert_refused('operation_unknown', lambda: self.call('/api/upload', payload))
        payload = self.payload(); first = self.call('/api/upload', payload)
        self.assertEqual(first, self.call('/api/upload', payload))
        self.assertEqual(1, sum(r['op'] == 'upload' for r in self.receiver.calls))

    def test_compaction_keeps_accepting_after_512_and_never_replays(self):
        self.confirmed(); oldest = None
        for _ in range(520):
            payload = self.payload()
            if oldest is None: oldest = payload
            self.call('/api/upload', payload)
        self.assertEqual(520, sum(r['op'] == 'upload' for r in self.receiver.calls))
        recent = self.call('/api/receipts', method='GET')
        self.assertEqual(32, len(recent['operations']))
        self.assert_refused('operation_unknown', lambda: self.call('/api/upload', oldest))
        self.assertEqual(520, sum(r['op'] == 'upload' for r in self.receiver.calls))

    def test_resolution_survives_restart_without_changing_result(self):
        self.confirmed()
        self.receiver.upload_result = {'ok': True, 'status': 'transferred',
            'attach': {'state': 'unverified'}, 'files': [{'attach': 'pasted-unverified'}]}
        payload = self.payload(); original = self.call('/api/upload', payload)['operation']
        resolution = self.call('/api/resolve', {'operation_id': payload['operation_id']})
        self.assertEqual('acknowledged', resolution['resolution']['state'])
        self.assertEqual(resolution, self.call('/api/resolve', {'operation_id': payload['operation_id']}))
        self.app.close()
        self.app = web.App('home.example.ts.net:9443', 'operator@example.test',
                           Path(self.tmp.name) / 'state', receiver=self.receiver)
        self.nonce = self.call('/api/session', {})['nonce']
        stored = self.call('/api/receipt/' + payload['operation_id'], method='GET')
        self.assertEqual(original, stored['operation'])
        self.assertEqual('acknowledged', stored['resolution']['state'])
        self.assertEqual(0, self.call('/api/receipts', method='GET')['unresolved'])

    def test_expired_replaced_and_slow_body_tickets_never_dispatch(self):
        self.confirmed(); old = self.payload(); current = self.payload()
        self.assert_refused('operation_unknown', lambda: self.call('/api/upload', old))
        self.clock[0] += web.TICKET_TTL
        self.assert_refused('operation_unknown', lambda: self.call('/api/upload', current))
        current = self.payload()
        class SlowBody(io.BytesIO):
            def read(stream, size):
                self.clock[0] += web.SESSION_TTL
                return super().read(size)
        raw = web.canonical(current)
        self.assert_refused('session', lambda: self.call('/api/upload', current, raw=raw,
                            stream=SlowBody(raw)))
        self.assertFalse(any(r['op'] == 'upload' for r in self.receiver.calls))

    def test_expiry_during_validation_prevents_durable_reservation(self):
        self.confirmed(); payload = self.payload(); validate = web.validate_images
        def slow(images, target=None):
            result = validate(images, target)
            self.clock[0] += web.TICKET_TTL
            return result
        with patch.object(web, 'validate_images', side_effect=slow):
            self.assert_refused('operation_unknown', lambda: self.call('/api/upload', payload))
        self.assertIsNone(self.app.journal.get(payload['operation_id']))
        self.assertFalse(any(r['op'] == 'upload' for r in self.receiver.calls))

    def test_server_owned_chat_selection_is_nonce_bound(self):
        other = str(uuid.uuid4())
        target = self.receiver({'op': 'target', 'thread': other})['target']
        self.receiver.catalog_result = {'ok': True, 'tmux_ok': True, 'complete': True,
            'truncated': False, 'threads': [other], 'chats': [{'target': target, 'composer': 'ready'}]}
        self.assert_refused('no_default', lambda: self.call('/api/target', {}))
        choice = self.call('/api/chats', method='GET')['chats'][0]
        self.assertFalse(choice['is_default'])
        old_nonce = self.nonce
        self.nonce = self.call('/api/session', {})['nonce']
        self.assert_refused('selection', lambda: self.call('/api/target',
                            {'selection_id': choice['selection_id']}))
        self.nonce = old_nonce
        selected = self.call('/api/target', {'selection_id': choice['selection_id']})
        self.call('/api/confirm', {'target_id': selected['target_id']})
        self.call('/api/upload', self.payload())
        self.assertEqual(other, self.receiver.calls[-1]['thread'])

    def test_legacy_over_capacity_is_preserved_and_readback_only(self):
        receipts = []
        with self.app.journal.db:
            for _ in range(70):
                ident = str(uuid.uuid4())
                receipt = {'operation_id': ident, 'state': 'uncertain', 'result': {'ok': False}}
                raw = web.canonical(receipt).decode(); receipts.append((ident, raw))
                self.app.journal.db.execute('INSERT INTO operations VALUES (?,?,?)',
                    (ident, web.validate_images([image()]), raw))
        self.app.close()
        self.app = web.App('home.example.ts.net:9443', 'operator@example.test',
                           Path(self.tmp.name) / 'state', receiver=self.receiver)
        self.nonce = self.call('/api/session', {})['nonce']; self.confirmed()
        recent = self.call('/api/receipts', method='GET')
        self.assertEqual(70, recent['unresolved']); self.assertEqual(70, len(recent['operations']))
        self.assert_refused('journal_full', self.payload)
        ident, raw = receipts[0]
        replay = self.call('/api/upload', {'protocol': 2, 'operation_id': ident, 'images': [image()]})
        self.assertEqual(json.loads(raw), replay['operation'])
        original = self.app.journal.db.execute('SELECT receipt FROM operations WHERE id=?', (ident,)).fetchone()[0]
        self.assertEqual(raw, original)
        self.assertFalse(any(r['op'] == 'upload' for r in self.receiver.calls))

    def test_identifier_counter_never_reuses_an_id_after_restart(self):
        with patch.object(web.secrets, 'randbits', return_value=0):
            first = self.app.journal.issue_id()
            self.app.close()
            self.app = web.App('home.example.ts.net:9443', 'operator@example.test',
                               Path(self.tmp.name) / 'state', receiver=self.receiver)
            second = self.app.journal.issue_id()
        self.assertNotEqual(first, second)

    def test_arbitrary_legacy_v8_id_cannot_exhaust_server_identifiers(self):
        poison = '11111111-1111-8111-bfff-ffffffffffff'
        with self.app.journal.db:
            self.app.journal.db.execute('INSERT INTO operations VALUES (?,?,?)',
                (poison, web.validate_images([image()]), web.canonical(
                    {'operation_id': poison, 'state': 'uncertain', 'result': {'ok': False}}).decode()))
        self.app.close()
        self.app = web.App('home.example.ts.net:9443', 'operator@example.test',
                           Path(self.tmp.name) / 'state', receiver=self.receiver)
        self.assertNotEqual(poison, self.app.journal.issue_id())

    def test_compacted_legacy_uuid_cannot_be_minted_as_a_new_ticket(self):
        old = '00000000-0000-8000-8000-000000000001'
        receipt = self.app.journal.reserve(old, web.validate_images([image()]))
        receipt.update(state='completed', result=self.receiver.upload_result)
        self.app.journal.finish(old, receipt)
        self.app.close()
        self.app = web.App('home.example.ts.net:9443', 'operator@example.test',
                           Path(self.tmp.name) / 'state', receiver=self.receiver)
        for _ in range(33):
            ident = str(uuid.uuid4()); receipt = self.app.journal.reserve(ident, 'fixture')
            receipt.update(state='completed', result=self.receiver.upload_result)
            self.app.journal.finish(ident, receipt)
        self.assertIsNone(self.app.journal.get(old))
        with patch.object(web.secrets, 'randbits', return_value=0):
            self.assertNotEqual(old, self.app.journal.issue_id())


class V5RetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = self.root / 'store'; self.store.mkdir(mode=0o700)
        self.batch = self.store / '20261001-010101-0123456789abcdef'; self.batch.mkdir(mode=0o700)
        self.path = self.batch / '01-0123456789ab.png'
        self.raw = b'\x89PNG\r\n\x1a\nfixture'
        self.path.write_bytes(self.raw); self.path.chmod(0o600)
        self.receiver = FakeReceiver()
        self.receiver.upload_result['files'] = [{'name': 'screen.png', 'size': len(self.raw),
            'sha256': hashlib.sha256(self.raw).hexdigest(), 'path': str(self.path),
            'attach': 'attached-verified'}]
        self.now = time.time()
        self.app = web.App('home.example.ts.net:9443', 'operator@example.test', self.root / 'state',
                           receiver=self.receiver, clock=lambda: 1.0, store=self.store,
                           wall_clock=lambda: self.now)
        self.nonce = self.app.api('POST', '/api/session', {}, None)['nonce']
        target = self.app.api('POST', '/api/target', {}, self.nonce)
        self.app.api('POST', '/api/confirm', {'target_id': target['target_id']}, self.nonce)
        ticket = self.app.api('POST', '/api/operations', {'protocol': 2}, self.nonce)
        self.ident = ticket['operation_id']
        receipt = self.app.api('POST', '/api/upload', {'protocol': 2, 'operation_id': self.ident,
                               'images': [image(raw=self.raw)]}, self.nonce)['operation']
        self.created = web.datetime.datetime.fromisoformat(receipt['created_at']).timestamp()
        os.utime(self.path, (self.created, self.created))
        self.receiver.catalog_result = {'ok': True, 'tmux_ok': True, 'complete': True,
                                        'truncated': False, 'threads': [], 'chats': []}

    def tearDown(self):
        self.app.close(); self.tmp.cleanup()

    def test_exact_seven_day_boundary_and_unmanaged_neighbor(self):
        neighbor = self.batch / '02-abcdef012345.png'; neighbor.write_bytes(self.raw)
        self.now = self.created + 7 * 86400 - 1
        self.app.maintenance(); self.assertTrue(self.path.exists())
        self.now += 1
        result = self.app.maintenance()
        self.assertFalse(self.path.exists()); self.assertEqual(1, result['deleted'])
        self.assertEqual(self.raw, neighbor.read_bytes())

    def test_present_or_incomplete_catalog_holds_file(self):
        self.now = self.created + 8 * 86400
        for catalog in (
            {'threads': [web.THREAD], 'complete': True, 'truncated': False},
            {'threads': [], 'complete': False, 'truncated': True},
        ):
            self.receiver.catalog_result.update(catalog)
            result = self.app.maintenance()
            self.assertTrue(self.path.exists()); self.assertEqual(1, result['held'])

    def test_changed_content_mode_symlink_and_future_mtime_are_held(self):
        self.now = self.created + 8 * 86400
        self.path.chmod(0o644); self.app.maintenance(); self.assertTrue(self.path.exists())
        self.path.chmod(0o600)
        self.path.write_bytes(b'changed bytes'); os.utime(self.path, (self.created, self.created))
        self.app.maintenance(); self.assertTrue(self.path.exists())
        self.path.write_bytes(self.raw); self.path.chmod(0o600)
        os.utime(self.path, (self.now + 1, self.now + 1))
        self.app.maintenance(); self.assertTrue(self.path.exists())
        self.path.unlink(); outside = self.root / 'outside'; outside.write_bytes(self.raw)
        self.path.symlink_to(outside); self.app.maintenance()
        self.assertTrue(self.path.is_symlink()); self.assertEqual(self.raw, outside.read_bytes())

    def test_upload_lock_skips_cleanup(self):
        self.now = self.created + 8 * 86400
        self.app.jobs.acquire()
        try:
            result = self.app.maintenance()
        finally:
            self.app.jobs.release()
        self.assertTrue(result['skipped']); self.assertTrue(self.path.exists())

    def test_no_eligible_rows_never_take_upload_lock(self):
        class NoAdmission:
            def acquire(self, **_): raise AssertionError('Cleanup blocked uploads with no eligible row')
        previous = self.app.jobs; self.app.jobs = NoAdmission()
        try:
            result = self.app.maintenance()
        finally:
            self.app.jobs = previous
        self.assertEqual(0, result['deleted']); self.assertTrue(self.path.exists())

    def test_any_live_codex_or_incomplete_process_scan_holds_all_files(self):
        self.now = self.created + 8 * 86400
        for fields in ({'process_complete': True, 'codex_present': True},
                       {'process_complete': False, 'codex_present': False}):
            self.receiver.catalog_result.update(fields)
            self.assertEqual(1, self.app.maintenance()['held']); self.assertTrue(self.path.exists())

    def test_missing_batch_is_missing_and_deleted_tombstone_survives_restart(self):
        self.now = self.created + 8 * 86400
        self.path.unlink(); self.batch.rmdir()
        result = self.app.maintenance()
        self.assertEqual(0, result['held']); self.assertIsNone(result['last_error'])
        row = self.app.journal.db.execute('SELECT state FROM managed_files').fetchone()
        self.assertEqual(('deleted',), row)
        self.app.close()
        self.app = web.App('home.example.ts.net:9443', 'operator@example.test', self.root / 'state',
            receiver=self.receiver, store=self.store, wall_clock=lambda: self.now)
        self.assertEqual(('deleted',), self.app.journal.db.execute('SELECT state FROM managed_files').fetchone())
        self.assertEqual(0, self.app.maintenance()['managed'])

    def test_receiver_cannot_reuse_retained_batch_tombstone(self):
        self.now = self.created + 8 * 86400
        self.assertEqual(1, self.app.maintenance()['deleted'])
        self.assertTrue(self.batch.is_dir()); self.assertFalse(self.path.exists())
        loader = importlib.machinery.SourceFileLoader('retention_receiver', str(ROOT / 'bin/codex-drop'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        native = importlib.util.module_from_spec(spec); loader.exec_module(native)
        with patch.object(native, 'open_store', side_effect=lambda: (os.open(self.store, native.DIR_FLAGS), str(self.store))), \
                patch.object(native.time, 'strftime', return_value='20261001-010101'), \
                patch.object(native.secrets, 'token_hex', return_value='0123456789abcdef'):
            with self.assertRaises(FileExistsError):
                native.store_images(native.validate_images([image(raw=self.raw)]))
        self.assertEqual([], list(self.batch.iterdir()))

    def test_unresolved_is_held_until_durable_acknowledgement(self):
        with self.app.journal.db:
            self.app.journal.db.execute("UPDATE managed_files SET state='unresolved'")
            receipt = self.app.journal.get(self.ident)[1]
            receipt['result']['attach']['state'] = 'unverified'
            self.app.journal.db.execute('UPDATE operations SET receipt=? WHERE id=?',
                                       (web.canonical(receipt).decode(), self.ident))
        self.now = self.created + 8 * 86400
        self.assertEqual(1, self.app.maintenance()['held']); self.assertTrue(self.path.exists())
        self.app.journal.acknowledge(self.ident)
        self.assertEqual(1, self.app.maintenance()['deleted']); self.assertFalse(self.path.exists())

    def test_hardlink_fifo_and_foreign_owner_are_held(self):
        self.now = self.created + 8 * 86400
        other = self.root / 'hardlink'; os.link(self.path, other)
        self.assertEqual(1, self.app.maintenance()['held']); other.unlink()
        real = os.fstat
        def foreign(fd):
            info = real(fd)
            if stat.S_ISREG(info.st_mode):
                values = list(info); values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return info
        with patch.object(web.os, 'fstat', side_effect=foreign):
            self.assertEqual(1, self.app.maintenance()['held'])
        self.path.unlink(); os.mkfifo(self.path, 0o600)
        self.assertEqual(1, self.app.maintenance()['held']); self.assertTrue(self.path.exists())

    def test_replaced_entry_or_newly_present_thread_is_held(self):
        self.now = self.created + 8 * 86400
        original = self.app.presence; count = 0
        def replace():
            nonlocal count
            count += 1
            if count == 2:
                new = self.batch / 'replacement'; new.write_bytes(self.raw); new.chmod(0o600)
                os.utime(new, (self.created, self.created)); os.replace(new, self.path)
            return original()
        with patch.object(self.app, 'presence', side_effect=replace):
            self.assertEqual(1, self.app.maintenance()['held'])
        count = 0
        def present():
            nonlocal count
            count += 1
            result = original()
            return {**result, 'threads': [web.THREAD]} if count > 1 else result
        with patch.object(self.app, 'presence', side_effect=present):
            self.assertEqual(1, self.app.maintenance()['held'])
        self.assertTrue(self.path.exists())

    def test_missing_or_symlinked_parent_is_not_created_or_followed(self):
        self.now = self.created + 8 * 86400
        saved = self.root / 'saved'; self.store.rename(saved)
        self.app.maintenance(); self.assertFalse(self.store.exists())
        self.store.symlink_to(saved, target_is_directory=True)
        self.app.maintenance(); self.assertTrue((saved / self.batch.name / self.path.name).exists())
        self.assertTrue(self.store.is_symlink())

    def test_partial_failure_reports_error_and_preserves_failed_file(self):
        self.now = self.created + 8 * 86400
        second = self.batch / '02-abcdef012345.png'; second.write_bytes(self.raw); second.chmod(0o600)
        os.utime(second, (self.created, self.created))
        ident = str(uuid.uuid4()); receipt = self.app.journal.get(self.ident)[1]
        receipt = json.loads(json.dumps(receipt)); receipt['operation_id'] = ident
        receipt['result']['files'][0]['path'] = str(second)
        self.app.journal.reserve(ident, 'fixture'); self.app.journal.finish(ident, receipt)
        unlink = os.unlink
        def denied(name, **kwargs):
            if name == self.path.name: raise PermissionError('fixture')
            return unlink(name, **kwargs)
        with patch.object(web.os, 'unlink', side_effect=denied):
            result = self.app.maintenance()
        self.assertEqual(1, result['deleted']); self.assertEqual(1, result['held'])
        self.assertEqual('PermissionError', result['last_error'])
        self.assertTrue(self.path.exists()); self.assertFalse(second.exists())

    def test_compacted_receipt_keeps_provenance_across_restart(self):
        for _ in range(33):
            ident = str(uuid.uuid4()); receipt = self.app.journal.reserve(ident, 'fixture')
            receipt.update(state='completed', result={'ok': True, 'attach': {'state': 'verified'},
                           'files': [{'attach': 'attached-verified'}]})
            self.app.journal.finish(ident, receipt)
        self.assertIsNone(self.app.journal.get(self.ident))
        self.app.close()
        self.now = self.created + 8 * 86400
        self.app = web.App('home.example.ts.net:9443', 'operator@example.test', self.root / 'state',
            receiver=self.receiver, store=self.store, wall_clock=lambda: self.now)
        self.assertEqual(1, self.app.maintenance()['deleted']); self.assertFalse(self.path.exists())

    def test_completed_provenance_migration_is_not_repeated(self):
        self.app.close()
        with patch.object(web.Journal, '_register_files', side_effect=AssertionError('Repeated adoption')):
            self.app = web.App('home.example.ts.net:9443', 'operator@example.test', self.root / 'state',
                receiver=self.receiver, store=self.store, wall_clock=lambda: self.now)
        self.assertEqual(1, self.app.journal.db.execute('SELECT count(*) FROM managed_files').fetchone()[0])


class V5FrontendRegressionTests(unittest.TestCase):
    setUp = FrontendTests.setUp
    run_node = FrontendTests.run_node
    def run_case(self, case):
        self.run_node(r'''
const h=globalThis.CodexDropTest;
const target={thread:'home',socket:'default',pane:'%1',pane_pid:2,window:'@1',tui_pid:3,tui_start:'4',session:'test',window_name:'test'};
const file=name=>({name,type:'image/png',size:12});
let n=0,mode='unknown',ops=[],uploads=[],receipts=[];
const operation=id=>({operation_id:id,state:'uncertain',result:{ok:false,error:{code:'outcome_uncertain'}}});
const api=async(method,path,body)=>{
 if(path==='/api/session')return{ok:true,nonce:'fixture',protocol:2,ttl_seconds:900,retention_days:7};
 if(path==='/api/receipts')return{ok:true,operations:receipts,unresolved:receipts.filter(o=>!o.resolution).length,unresolved_capacity:64};
 if(path==='/api/chats')return{ok:true,chats:[{selection_id:'opaque',target,composer:'ready',is_default:true}]};
 if(path==='/api/target')return{ok:true,target_id:'confirmed',target,composer:'ready',is_default:true};
 if(path==='/api/confirm')return{ok:true,confirmed:true,target};
 if(path==='/api/operations'){let id='11111111-1111-4111-8111-'+String(++n).padStart(12,'0');ops.push(id);return{ok:true,operation_id:id,expires_in:60};}
 if(path==='/api/upload'){uploads.push(body);if(mode==='unknown')return{ok:false,http_status:410,error:{code:'operation_unknown',message:'Expired'}};receipts=[operation(body.operation_id)];return{ok:true,operation:receipts[0]};}
 if(path.startsWith('/api/receipt/'))return receipts.length?{ok:true,operation:receipts[0]}:{ok:false,http_status:404,error:{code:'receipt_missing'}};
 if(path==='/api/resolve'){let resolution={state:'acknowledged',at:'2026-10-19T00:00:00Z'};receipts.forEach(o=>o.resolution=resolution);return{ok:true,resolution};}
 throw Error('unexpected route '+path);
};
const c=h.createController({api,prepare:async fs=>fs.map(f=>({name:f.name,size:f.size,sha256:'a'.repeat(64),data:'fixture'})),preview:()=>null});
(async()=>{await c.connect();await c.confirmChat();
''' + case + r'''
c.dispose();})().catch(e=>{console.error(e);process.exitCode=1});
''')

    def test_compacted_receipt_does_not_claim_never_attached(self):
        self.run_case(r'''
await c.addFiles([file('one.png')]);
assert.equal(uploads.length,1);
assert.equal(c.state.operationId,ops[0]);
assert.doesNotMatch(c.state.error.message,/nothing was attached|never dispatched|nothing was dispatched/i);
assert.match(c.state.error.message,/inspect|check.*draft/i);
''')

    def test_acknowledgement_does_not_arm_old_queued_files(self):
        self.run_case(r'''
mode='uncertain';await c.addFiles([file('old.png')]);assert.equal(uploads.length,1);
await c.inspect();assert.equal(await c.retry(true),true);
await c.addFiles([file('fresh.png')]);
assert.equal(uploads.length,1,'Acknowledging an incident must not let a later drop resend the old queued screenshot');
assert.equal(c.state.queue.length,2);
''')

    def test_missing_receipt_copy_remains_uncertain_after_inspection(self):
        self.run_case(r'''
await c.addFiles([file('one.png')]);await c.inspect();
assert.equal(c.state.inspected.kind,'missing');
assert.doesNotMatch(h.missingText(c.state.inspected.operation_id),/never dispatched|nothing was (attached|dispatched)/i);
''')

    def test_expiry_and_resume_do_not_rearm_queued_files(self):
        self.run_node(r'''
const h=globalThis.CodexDropTest, calls=[];
let now=1000,session=0,confirmations=0,changed=false,failPrepare=true;
const target={thread:'home',socket:'default',pane:'%1',pane_pid:'2',window:'@1',tui_pid:'3',tui_start:'4',session:'test',window_name:'test'};
const current=()=>({...target,tui_pid:changed?'changed':'3'});
const api=async(method,path,body)=>{
 calls.push(path);
 if(path==='/api/session')return{ok:true,nonce:'session-'+(++session),protocol:2,ttl_seconds:900,retention_days:7};
 if(path==='/api/receipts')return{ok:true,operations:[],unresolved:0,unresolved_capacity:64};
 if(path==='/api/chats')return{ok:true,chats:[{selection_id:'opaque',target:current(),composer:'ready',is_default:true}]};
 if(path==='/api/target')return{ok:true,target_id:'ref',target:current(),composer:'ready'};
 if(path==='/api/confirm'){confirmations++;return{ok:true,confirmed:true,target:current()};}
 if(path==='/api/operations')return{ok:true,operation_id:'11111111-1111-4111-8111-111111111111'};
 if(path==='/api/upload')return{ok:true,operation:{operation_id:body.operation_id,state:'completed',result:{ok:true,attach:{state:'verified'},files:[{attach:'attached-verified'}]}}};
 throw Error(path);
};
const c=h.createController({api,now:()=>now,prepare:async files=>{if(failPrepare)throw Error('read failed');return files.map(f=>({name:f.name}));}});
(async()=>{
 await c.connect();assert.equal(c.state.confirmed,false);await c.confirmChat();
 await c.addFiles([{name:'old.png',type:'image/png',size:12}]);assert.equal(c.state.armed,false);
 now+=901000;await c.resume();assert.equal(session,2);assert.equal(confirmations,2);
 assert.equal(c.state.confirmed,true);assert.equal(c.state.armed,false,'Renewal must not rearm failed queued files');
 failPrepare=false;await c.addFiles([{name:'new.png',type:'image/png',size:12}]);
 assert.equal(calls.filter(x=>x==='/api/upload').length,0);
 await c.send();assert.equal(calls.filter(x=>x==='/api/upload').length,1);
 now+=901000;changed=true;await c.resume();assert.equal(c.state.confirmed,false);
 assert.equal(confirmations,2,'A changed physical chat must require explicit confirmation');
 assert.equal(calls.filter(x=>x==='/api/upload').length,1);c.dispose();
})().catch(e=>{console.error(e);process.exitCode=1});
''')


class FreshDropFrontendTests(unittest.TestCase):
    setUp = FrontendTests.setUp
    run_node = FrontendTests.run_node

    def run_case(self, case):
        self.run_node(r'''
const h=globalThis.CodexDropTest;
const file=name=>({name,type:'image/png',size:12});
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const until=async p=>{for(let i=0;i<100&&!p();i++)await tick();assert.ok(p(),'fixture did not reach held read');};
function fixture(){
 let now=100000,gate=null,seq=0,session=0,changed=false,readFailure=null,prepareFailure=false,preparationGate=null,receipts=[],protocol=2;
 const calls=[],prepared=[],uploads=[];
 const target={thread:'home',socket:'default',pane:'%1',pane_pid:'2',window:'@1',tui_pid:'3',tui_start:'4',session:'test',window_name:'test'};
 const current=()=>({...target,tui_pid:changed?'other':'3'});
 const api=async(method,path,body)=>{
  calls.push(path);
  if(gate&&gate.path===path&&!gate.entered){gate.entered=true;await gate.promise;}
  if(readFailure===path)return{ok:false,error:{code:'read_failed',message:'Fixture refusal'}};
  if(path==='/api/session')return{ok:true,nonce:'session-'+(++session),protocol,ttl_seconds:900,retention_days:7};
  if(path==='/api/receipts')return{ok:true,operations:receipts,unresolved:receipts.length,unresolved_capacity:64};
  if(path==='/api/chats')return{ok:true,chats:[{selection_id:'opaque',target:current(),composer:'ready',is_default:true}]};
  if(path==='/api/target')return{ok:true,target_id:'reference',target:current(),composer:'ready'};
  if(path==='/api/confirm')return{ok:true,confirmed:true,target:current()};
  if(path==='/api/operations')return{ok:true,operation_id:'11111111-1111-4111-8111-'+String(++seq).padStart(12,'0')};
  if(path==='/api/upload'){uploads.push(body);return{ok:true,operation:{operation_id:body.operation_id,state:'completed',result:{ok:true,attach:{state:'verified'},files:body.images.map(x=>({name:x.name,attach:'attached-verified'}))}}};}
  throw Error('Unexpected endpoint '+path);
 };
 const c=h.createController({api,now:()=>now,preview:()=>null,prepare:async files=>{
  prepared.push(files.map(x=>x.name));if(prepareFailure)throw Error('Fixture file read failure');
  if(preparationGate){preparationGate.entered=true;await preparationGate.promise;}
  return files.map(x=>({name:x.name,size:x.size,sha256:'a'.repeat(64),data:'fixture'}));
 }});
 return{c,calls,prepared,uploads,expire(){now+=901000;},change(){changed=true;},
  failure(path){readFailure=path;},prepareFailure(v){prepareFailure=v;},protocol(v){protocol=v;},
  incident(){receipts=[{operation_id:'11111111-1111-4111-8111-999999999999',state:'uncertain',result:{ok:false,error:{code:'outcome_uncertain'}}}];},
  holdPreparation(){let resolve;const promise=new Promise(r=>resolve=r);preparationGate={promise,resolve,entered:false};return preparationGate;},
  hold(path){let resolve;const promise=new Promise(r=>resolve=r);gate={path,promise,resolve,entered:false};return gate;}};
}
(async()=>{
''' + case + r'''
})().catch(e=>{console.error(e);process.exitCode=1});
''')

    def test_fresh_drop_survives_same_readiness_check_once(self):
        self.run_case(r'''
for(const renewal of [false,true]){
 const f=fixture();await f.c.connect();await f.c.confirmChat();if(renewal)f.expire();
 const gate=f.hold(renewal?'/api/session':'/api/receipts');const refresh=f.c.resume();await until(()=>gate.entered);
 const drop=f.c.addFiles([file('fresh.png')]);await tick();assert.equal(f.uploads.length,0);
 assert.match(f.c.state.message,/1.*(?:will attach|check finishes|checking)/i);
 gate.resolve();await Promise.all([refresh,drop]);
 assert.equal(f.uploads.length,1,'Fresh gesture must finish without an Attach click');
 assert.deepEqual(f.prepared,[['fresh.png']]);assert.equal(f.calls.filter(x=>x==='/api/operations').length,1);
 assert.deepEqual(f.uploads[0].images.map(x=>x.name),['fresh.png']);f.c.dispose();
}
''')

    def test_multiple_fresh_drops_merge_into_one_bounded_upload(self):
        self.run_case(r'''
const f=fixture();await f.c.connect();await f.c.confirmChat();const gate=f.hold('/api/chats');
const refresh=f.c.resume();await until(()=>gate.entered);
const a=f.c.addFiles([file('one.png')]),b=f.c.addFiles([file('two.png')]);
assert.equal(await f.c.addFiles(Array(11).fill(file('excess.png'))),false);
gate.resolve();await Promise.all([refresh,a,b]);
assert.equal(f.uploads.length,1);assert.deepEqual(f.prepared,[['one.png','two.png']]);
assert.deepEqual(f.uploads[0].images.map(x=>x.name),['one.png','two.png']);f.c.dispose();
''')

    def test_readiness_without_gesture_never_prepares_or_uploads(self):
        self.run_case(r'''
const f=fixture();await f.c.connect();await f.c.confirmChat();await f.c.resume();
assert.equal(f.prepared.length,0);assert.equal(f.uploads.length,0);
assert.equal(f.calls.filter(x=>x==='/api/operations').length,0);f.c.dispose();
''')

    def test_failed_reads_cancel_fresh_intent_and_offer_reconnect(self):
        self.run_case(r'''
for(const path of ['/api/receipts','/api/chats','/api/session']){
 const f=fixture();await f.c.connect();await f.c.confirmChat();if(path==='/api/session')f.expire();
 const gate=f.hold(path);const refresh=f.c.resume();await until(()=>gate.entered);
 const drop=f.c.addFiles([file('fresh.png')]);f.failure(path);gate.resolve();await Promise.all([refresh,drop]);
 assert.equal(f.uploads.length,0);assert.equal(f.c.state.armed,false);
 assert.equal(f.c.state.connected,false);assert.equal(f.c.state.confirmed,false);
 assert.match((f.c.state.message||'')+' '+(f.c.state.error?.message||''),/could(?: not|n't).*check|reconnect/i);
 await f.c.addFiles([file('later.png')]);assert.equal(f.uploads.length,0);
 f.failure(null);await f.c.connect();assert.equal(f.c.state.confirmed,false,'Reconnect must require a new explicit confirmation');
 assert.equal(f.uploads.length,0);f.c.dispose();
}
''')

    def test_late_drop_cannot_start_another_upload_after_drain_claim(self):
        self.run_case(r'''
const f=fixture();await f.c.connect();await f.c.confirmChat();
const preparing=f.holdPreparation(),gate=f.hold('/api/chats');const refresh=f.c.resume();await until(()=>gate.entered);
const drop=f.c.addFiles([file('fresh.png')]);gate.resolve();await until(()=>preparing.entered);
assert.equal(await f.c.addFiles([file('too-late.png')]),false);
preparing.resolve();await Promise.all([refresh,drop]);assert.equal(f.uploads.length,1);
assert.deepEqual(f.uploads[0].images.map(x=>x.name),['fresh.png']);f.c.dispose();
''')

    def test_new_uncertain_receipt_cancels_pending_fresh_upload(self):
        self.run_case(r'''
const f=fixture();await f.c.connect();await f.c.confirmChat();const gate=f.hold('/api/receipts');
const refresh=f.c.resume();await until(()=>gate.entered);const drop=f.c.addFiles([file('fresh.png')]);
f.incident();gate.resolve();await Promise.all([refresh,drop]);
assert.equal(f.uploads.length,0);assert.equal(f.prepared.length,0);assert.equal(f.c.state.needsAck,true);
assert.equal(f.c.state.armed,false);f.c.dispose();
''')

    def test_protocol_refusal_preserves_reload_instruction(self):
        self.run_case(r'''
const f=fixture();await f.c.connect();await f.c.confirmChat();f.expire();f.protocol(1);
await f.c.resume();assert.equal(f.c.state.reloadRequired,true);assert.equal(f.c.state.connected,false);
assert.equal(f.c.state.error.code,'protocol_reload');assert.match(f.c.state.error.message,/out of date.*reload/i);
assert.equal(f.uploads.length,0);f.c.dispose();
''')

    def test_successful_automatic_check_clears_readiness_failure(self):
        self.run_case(r'''
const f=fixture();await f.c.connect();await f.c.confirmChat();f.failure('/api/receipts');await f.c.resume();
assert.equal(f.c.state.error.code,'readiness_failed');f.failure(null);f.expire();await f.c.resume();
assert.equal(f.c.state.connected,true);assert.equal(f.c.state.confirmed,false);
assert.equal(f.c.state.error,null);assert.equal(f.uploads.length,0);f.c.dispose();
''')

    def test_failed_check_invalidates_session_until_reconnect(self):
        self.run_case(r'''
for(const path of ['/api/receipts','/api/chats']){
 const f=fixture();await f.c.connect();await f.c.confirmChat();f.failure(path);await f.c.resume();
 const confirmations=f.calls.filter(x=>x==='/api/confirm').length;
 assert.equal(await f.c.confirmChat(),false);assert.equal(f.c.state.confirmed,false);
 assert.equal(f.calls.filter(x=>x==='/api/confirm').length,confirmations);
 assert.equal(f.c.state.error.code,'readiness_failed');
 assert.equal(await f.c.refreshTarget(),false);assert.equal(await f.c.selectChat(0),false);
 assert.equal(f.uploads.length,0);f.c.dispose();
}
''')

    def test_changed_target_or_user_cancellation_never_uploads(self):
        self.run_case(r'''
for(const action of ['change','remove','clear','select','dispose']){
 const f=fixture();await f.c.connect();await f.c.confirmChat();const gate=f.hold('/api/chats');
 const refresh=f.c.resume();await until(()=>gate.entered);const drop=f.c.addFiles([file('fresh.png')]);
 if(action==='change')f.change();else if(action==='remove')f.c.remove(0);
 else if(action==='clear')f.c.clear();else if(action==='select')await f.c.selectChat(0);else f.c.dispose();
 gate.resolve();await Promise.all([refresh,drop]);assert.equal(f.uploads.length,0,action);
 assert.equal(f.c.state.armed,false,action+' must consume automatic intent');f.c.dispose();
}
''')

    def test_old_failed_queue_and_unconfirmed_snapshot_never_auto_upload(self):
        self.run_case(r'''
for(const prior of ['failed','unconfirmed']){
 const f=fixture();await f.c.connect();
 if(prior==='failed'){await f.c.confirmChat();f.prepareFailure(true);await f.c.addFiles([file('old.png')]);f.prepareFailure(false);}
 const gate=f.hold('/api/chats');const refresh=f.c.resume();await until(()=>gate.entered);
 const drop=f.c.addFiles([file('new.png')]);gate.resolve();await Promise.all([refresh,drop]);
 assert.equal(f.uploads.length,0);assert.equal(f.c.state.armed,false);f.c.dispose();
}
''')

    def test_manual_queue_is_not_uploaded_by_a_later_drop(self):
        self.run_case(r'''
const f=fixture();await f.c.connect();await f.c.confirmChat();const gate=f.hold('/api/chats');
const refresh=f.c.refreshTarget();await until(()=>gate.entered);await f.c.addFiles([file('manual.png')]);
assert.equal(f.c.state.armed,false);assert.match(f.c.state.message,/1.*(?:queued|selected).*Attach selected/i);
gate.resolve();await refresh;await f.c.addFiles([file('later.png')]);
assert.equal(f.uploads.length,0);assert.equal(f.c.state.queue.length,2);f.c.dispose();
''')

    def test_first_use_queue_announces_action_without_fake_recovery(self):
        self.run_case(r'''
const f=fixture();await f.c.connect();await f.c.addFiles([file('first.png')]);
assert.match(f.c.state.message,/1.*selected.*Use this chat.*Attach selected/i);
await f.c.confirmChat();assert.equal(f.c.state.armed,false);assert.equal(f.uploads.length,0);
assert.match(f.c.state.message,/Attach selected/i);assert.doesNotMatch(f.c.state.message,/mark.*checked|check the Codex draft/i);f.c.dispose();
''')

    def test_expired_badge_can_wrap(self):
        page = self.path.read_text()
        badge = re.search(r'\.badge\s*\{([^}]+)\}', page).group(1)
        self.assertRegex(badge, r'white-space:\s*normal')
        self.assertRegex(badge, r'overflow-wrap:\s*anywhere')


if __name__ == '__main__':
    unittest.main(verbosity=2)
