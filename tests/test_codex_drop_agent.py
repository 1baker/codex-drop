"""Synthetic CLI/transport acceptance; no browser, model, SSH or live chat."""
import concurrent.futures
import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zlib

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'bin' / 'codex-drop-agent'


def load_module():
    loader = importlib.machinery.SourceFileLoader('drop_agent_test', str(CLI))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


agent = load_module()


def png(red):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 2, 2, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress((bytes([0, red, 40, 80, red, 40, 80])) * 2))
            + chunk(b'IEND', b''))


def pixels(data):
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    pos, compressed, dimensions = 8, b'', None
    while pos < len(data):
        length = struct.unpack('>I', data[pos:pos + 4])[0]
        kind, raw = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]
        assert zlib.crc32(kind + raw) == struct.unpack('>I', data[pos + 8 + length:pos + 12 + length])[0]
        if kind == b'IHDR':
            dimensions = struct.unpack('>IIBBBBB', raw)
        elif kind == b'IDAT':
            compressed += raw
        pos += length + 12
    assert pos == len(data) and dimensions == (2, 2, 8, 2, 0, 0, 0)
    return zlib.decompress(compressed)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class AgentWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='drop-agent-fixture-')
        self.base = Path(self.temp.name)
        self.inputs = self.base / 'inputs'
        self.inputs.mkdir(mode=0o700)
        self.exports = {}
        for purpose in agent.PURPOSES:
            path = self.base / purpose
            path.mkdir(mode=0o700)
            self.exports[purpose] = {'path': str(path), 'purpose': purpose}
        self.store = self.base / 'task-store'
        self.images = [png(10), png(220)]
        for i, data in enumerate(self.images):
            (self.inputs / f'{i}.png').write_bytes(data)
        self.seq = 0
        self.old_umask = os.umask(0o077)

    def tearDown(self):
        os.umask(self.old_umask)
        self.temp.cleanup()

    def request(self, operation, payload, kind='codex', task='fixture-task', op_id=None):
        self.seq += 1
        req = dict(schema=1, task_id=task, owner_id='fixture-owner',
                   consumer=dict(kind=kind, id=kind + '-fixture'), operation=operation, payload=payload)
        if operation != 'inspect':
            req['operation_id'] = op_id or f'op-{self.seq}'
        return req

    def init_request(self, **kw):
        return self.request('init', dict(consumers=[dict(kind=k, id=k + '-fixture') for k in agent.KINDS],
                           sources=dict(input=dict(path=str(self.inputs)),
                                        transport=dict(path=self.exports['iteration']['path'])),
                           exports=self.exports), **kw)

    def source(self, n=0):
        return dict(root='input', path=f'{n}.png', sha256=sha(self.images[n]))

    def cli(self, request, store=None, expected=0):
        command = [sys.executable, '-I', '-B', str(CLI), 'run', '--store', str(store or self.store),
                   '--request-file', '-']
        reply = subprocess.run(command, input=json.dumps(request), capture_output=True, text=True,
                               timeout=30)
        self.assertEqual(reply.returncode, expected, reply.stdout + reply.stderr)
        self.assertEqual(reply.stderr, '')
        result = json.loads(reply.stdout)
        self.assertLess(len(reply.stdout), 65536)
        self.assertNotIn('iVBORw0KGgo', reply.stdout)
        return result

    def initialize(self):
        return self.cli(self.init_request())

    def ingest(self, **kw):
        return self.cli(self.request('ingest', dict(files=[self.source(0), self.source(1)]), **kw))

    def receipts(self, op, store=None, task='fixture-task', expected=0):
        reply = subprocess.run([sys.executable, '-I', '-B', str(CLI), 'receipt', '--store',
                                str(store or self.store), '--task', task, '--operation', op],
                               capture_output=True, text=True, timeout=20)
        self.assertEqual(reply.returncode, expected, reply.stdout + reply.stderr)
        return json.loads(reply.stdout)

    def no_artifact_files(self):
        self.assertEqual(list(self.store.glob('a*.*')), [])

    def assert_code(self, req, code, **kw):
        self.assertEqual(self.cli(req, expected=2, **kw)['error']['code'], code)

    def test_both_documented_clients_full_local_handoff(self):
        for kind in agent.KINDS:
            with self.subTest(kind=kind):
                store = self.base / ('sender-' + kind)
                self.cli(self.init_request(kind=kind), store)
                imported = self.cli(self.request('ingest', dict(files=[self.source(0), self.source(1)]),
                                                 kind=kind), store)
                before, after = imported['artifacts']
                self.assertEqual(pixels(Path(before['path']).read_bytes()),
                                 bytes([0, 10, 40, 80, 10, 40, 80]) * 2)
                for meta, original in zip(imported['artifacts'], self.images):
                    self.assertEqual(Path(meta['path']).read_bytes(), original)
                    self.assertEqual(meta['sha256'], sha(original))
                    self.assertEqual(Path(meta['path']).stat().st_mode & 0o777, 0o600)
                    checked = self.cli(self.request('inspect', dict(artifact_id=meta['id']), kind=kind), store)
                    self.assertEqual(checked['artifact'], meta)
                    self.assertEqual(checked['validation'], 'bytes_sha256_and_signature_only')
                    self.assertEqual(checked['stages']['model_consumption'], 'not_observed')
                pair_req = self.request('pair', dict(before=before['id'], after=after['id'],
                                        before_revision='fixture-v1', after_revision='fixture-v2',
                                        criteria='Synthetic red channel changes.'), kind=kind)
                pair = self.cli(pair_req, store)
                self.assertFalse(pair['pair']['bytes_equal'])
                self.assertEqual(pair['pair']['before']['sha256'], before['sha256'])
                self.assertEqual(pair['pair']['after']['sha256'], after['sha256'])
                for subject in (dict(artifact_id=after['id']), dict(pair_operation_id=pair_req['operation_id'])):
                    fb = self.cli(self.request('feedback', dict(subject=subject, verdict='note',
                                  finding='Synthetic fixture observation; no model read performed.',
                                  spec_sha256='a' * 64), kind=kind), store)
                    self.assertEqual(fb['feedback']['assertion'], 'agent_attested_not_verified_vision')
                for purpose in agent.PURPOSES:
                    promoted = self.cli(self.request('promote', dict(artifact_id=after['id'],
                                destination=dict(root=purpose, path=kind + '.png'), purpose=purpose),
                                kind=kind), store)
                    self.assertEqual(Path(promoted['destination_path']).read_bytes(), self.images[1])
                    self.assertEqual(promoted['stages']['delivery'], 'performed')
                    self.assertEqual(promoted['stages']['public_publication'], 'not_performed')
                    self.assertEqual(promoted['stages']['training'], 'not_performed')
                pack = self.cli(self.request('pack', dict(artifact_ids=[before['id'], after['id']],
                                destination=dict(root='iteration', path=kind + '.json')), kind=kind), store)
                self.assertEqual(pack['stages']['delivery'], 'not_performed')
                self.assertEqual(sha(Path(pack['destination_path']).read_bytes()), pack['bundle']['sha256'])
                other = self.base / ('receiver-' + kind)
                task = 'receiver-' + kind
                self.cli(self.init_request(kind=kind, task=task), other)
                req = self.request('unpack', dict(source=dict(root='transport', path=kind + '.json',
                                    sha256=pack['bundle']['sha256'])), kind=kind, task=task)
                delivered = self.cli(req, other)
                self.assertFalse(delivered['sender_identity_verified'])
                self.assertEqual(delivered['stages']['delivery'], 'performed')
                for meta, original in zip(delivered['artifacts'], self.images):
                    self.assertEqual(Path(meta['path']).read_bytes(), original)
                    self.assertEqual(sha(Path(meta['path']).read_bytes()), meta['sha256'])
                self.assertEqual(self.receipts(req['operation_id'], other, task), delivered)
                self.assertEqual(self.cli(req, other), delivered)
                self.assertFalse(delivered['retention']['part_of_web_cleanup'])
                self.assertFalse(delivered['retention']['automatic_cleanup'])

    def test_idempotent_init_and_context_never_rewritten(self):
        req = self.init_request()
        first = self.cli(req)
        context = self.store / 'context.json'
        inode, content = context.stat().st_ino, context.read_bytes()
        self.assertEqual(self.cli(req), first)
        self.assertEqual(context.stat().st_ino, inode)
        self.assertEqual(context.read_bytes(), content)
        changed = self.init_request()
        changed['payload']['consumers'] = [changed['consumer']]
        self.assert_code(changed, 'context_mismatch')

    def test_wrong_owner_task_consumer_and_nested_unknown_fields(self):
        self.initialize()
        req = self.request('ingest', dict(files=[self.source()]))
        for key, value in [('owner_id', 'wrong'), ('task_id', 'wrong'),
                           ('consumer', dict(kind='claude', id='unregistered'))]:
            bad = copy.deepcopy(req); bad[key] = value
            self.assert_code(bad, 'context_mismatch')
        for edit in (lambda x: x.update(extra=1), lambda x: x['payload'].update(extra=1),
                     lambda x: x['payload']['files'][0].update(extra=1),
                     lambda x: x['consumer'].update(extra=1)):
            bad = copy.deepcopy(req); edit(bad)
            self.assert_code(bad, 'malformed')
        for key, value in [('schema', True), ('operation', 'capture'), ('operation_id', '../op')]:
            bad = copy.deepcopy(req); bad[key] = value
            self.cli(bad, expected=2)
        self.no_artifact_files()

    def test_strict_request_bounds_duplicate_json_and_no_error_echo(self):
        bad_inputs = ['{"schema":1,"schema":1}', '{"n":NaN}', '[' * 2000,
                      ' ' * (agent.MAX_REQUEST + 1)]
        for raw in bad_inputs:
            reply = subprocess.run([sys.executable, '-I', '-B', str(CLI), 'run', '--store',
                                    str(self.store), '--request-file', '-'], input=raw,
                                   capture_output=True, text=True, timeout=10)
            self.assertEqual(reply.returncode, 2)
            self.assertFalse(json.loads(reply.stdout)['ok'])
            self.assertLess(len(reply.stdout), 1000)
        reply = subprocess.run([sys.executable, '-I', '-B', str(CLI), 'untrusted-secret-command'],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(reply.returncode, 2)
        self.assertNotIn('untrusted-secret', reply.stdout + reply.stderr)
        self.assertEqual(json.loads(reply.stdout)['error']['code'], 'malformed')

    def test_source_paths_links_fifo_and_size_refuse_before_storage(self):
        self.initialize()
        for path in ('../0.png', '/0.png', './0.png', 'a//b', 'a\\b', 'a\nb',
                     '/'.join(['a'] * 17), 'a' * 513):
            self.assert_code(self.request('ingest', dict(files=[dict(self.source(), path=path)])), 'unsafe_path')
        outside = self.base / 'outside'
        outside.mkdir(mode=0o700)
        (outside / '0.png').write_bytes(self.images[0])
        os.symlink(outside, self.inputs / 'linked-dir')
        os.symlink(outside / '0.png', self.inputs / 'linked.png')
        os.link(outside / '0.png', self.inputs / 'hard.png')
        os.mkfifo(self.inputs / 'fifo')
        with (self.inputs / 'large.png').open('wb') as f:
            f.truncate(agent.MAX_IMAGE + 1)
        for path in ('linked-dir/0.png', 'linked.png', 'hard.png', 'fifo', 'large.png'):
            self.cli(self.request('ingest', dict(files=[dict(self.source(), path=path)])), expected=2)
        self.assert_code(self.request('ingest', dict(files=[dict(self.source(), sha256='0' * 64)])),
                         'hash_mismatch')
        (self.inputs / 'bad.png').write_bytes(b'not an image')
        self.assert_code(self.request('ingest', dict(files=[dict(root='input', path='bad.png',
                         sha256=sha(b'not an image'))])), 'not_image')
        self.no_artifact_files()

    def test_source_growing_during_read_and_replaced_root(self):
        self.initialize()
        source = self.inputs / '0.png'
        real_read = os.read
        inode = source.stat().st_ino
        altered = [False]
        def growing(fd, n):
            value = real_read(fd, n)
            if not altered[0] and os.fstat(fd).st_ino == inode:
                altered[0] = True
                with source.open('ab') as out:
                    out.write(b'changed')
            return value
        with mock.patch.object(agent.os, 'read', growing):
            with self.assertRaises(agent.AgentError) as error:
                agent.run_request(str(self.store), self.request('ingest', dict(files=[self.source()])))
            self.assertEqual(error.exception.code, 'source_changed')
        self.inputs.rename(self.base / 'old-inputs')
        self.inputs.mkdir(mode=0o700)
        source.write_bytes(self.images[0])
        self.assert_code(self.request('ingest', dict(files=[self.source()])), 'root_changed')
        self.no_artifact_files()

    def test_store_modes_symlinks_links_partial_context_and_mismatch(self):
        unsafe_parent = self.base / 'unsafe'
        unsafe_parent.mkdir(mode=0o777)
        unsafe_parent.chmod(0o777)
        self.assert_code(self.init_request(), 'store_unsafe', store=unsafe_parent / 'store')
        alias = self.base / 'alias'
        os.symlink(self.inputs, alias)
        self.cli(self.init_request(), alias / 'store', expected=2)
        self.initialize()
        for name in ('.lock', 'ledger.sqlite', 'context.json'):
            path = self.store / name
            path.chmod(0o644)
            self.cli(self.request('ingest', dict(files=[self.source()])), expected=2)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            path.chmod(0o600)
            link = self.base / (name.replace('.', '_') + '-link')
            os.link(path, link)
            self.cli(self.request('ingest', dict(files=[self.source()])), expected=2)
            link.unlink()
        journal = self.store / 'ledger.sqlite-journal'
        os.symlink(self.inputs / '0.png', journal)
        self.cli(self.request('ingest', dict(files=[self.source()])), expected=2)
        self.assertTrue(journal.is_symlink())
        journal.unlink()
        original = (self.store / 'context.json').read_bytes()
        (self.store / 'context.json').write_bytes(original + b' ')
        self.assert_code(self.request('ingest', dict(files=[self.source()])), 'store_incomplete')
        self.no_artifact_files()

    def test_partial_bootstrap_never_repaired(self):
        real_write = agent.write_file
        def stop_after_temp(parent, name, data):
            real_write(parent, name, data)
            if name == 'context.tmp':
                raise RuntimeError('fixture stopped bootstrap')
        req = self.init_request()
        with mock.patch.object(agent, 'write_file', stop_after_temp):
            with self.assertRaises(RuntimeError):
                agent.run_request(str(self.store), req)
        self.assertTrue((self.store / 'context.tmp').exists())
        before = {p.name: p.stat().st_ino for p in self.store.iterdir()}
        self.cli(req, expected=2)
        self.assertEqual({p.name: p.stat().st_ino for p in self.store.iterdir()}, before)

    def test_leftover_bootstrap_lock_is_not_repaired(self):
        self.store.mkdir(mode=0o700)
        lock = self.store / '.lock'
        lock.write_bytes(b'')
        lock.chmod(0o600)
        inode = lock.stat().st_ino
        self.assert_code(self.init_request(), 'store_incomplete')
        self.assertEqual(list(self.store.iterdir()), [lock])
        self.assertEqual(lock.stat().st_ino, inode)

    def test_new_init_id_consumes_quota_without_rewriting_context(self):
        self.initialize()
        path = self.store / 'context.json'
        inode, data = path.stat().st_ino, path.read_bytes()
        self.cli(self.init_request())
        self.assertEqual((path.stat().st_ino, path.read_bytes()), (inode, data))
        with mock.patch.object(agent, 'MAX_OPERATIONS', 2):
            with self.assertRaises(agent.AgentError) as error:
                agent.run_request(str(self.store), self.request('ingest', dict(files=[self.source()])))
            self.assertEqual(error.exception.code, 'quota_exhausted')
        self.no_artifact_files()

    def test_replay_concurrency_and_conflicting_request(self):
        self.initialize()
        req = self.request('ingest', dict(files=[self.source()]))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.cli(req), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(len(list(self.store.glob('a*.png'))), 1)
        self.assertEqual(self.receipts(req['operation_id']), results[0])
        changed = copy.deepcopy(req)
        changed['payload']['files'] = [self.source(1)]
        self.assert_code(changed, 'operation_conflict')
        self.assertEqual(self.cli(req), results[0])

    def crash(self, phase, req):
        script = '''import importlib.machinery,importlib.util,sys,json,os
loader=importlib.machinery.SourceFileLoader('fixture_agent',sys.argv[1])
spec=importlib.util.spec_from_loader(loader.name,loader)
m=importlib.util.module_from_spec(spec); loader.exec_module(m)
os.umask(0o077)
phase=sys.argv[3]
if phase=='reserve':
 old=m.reserve
 def crash(*a,**k):
  old(*a,**k); os._exit(77)
 m.reserve=crash
elif phase=='write':
 old=m.write_file
 def crash(*a,**k):
  old(*a,**k); os._exit(77)
 m.write_file=crash
else:
 def crash(*a,**k): os._exit(77)
 m.finish=crash
m.run_request(sys.argv[2],json.load(sys.stdin))
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(CLI),
                                 str(self.store), phase], input=json.dumps(req), capture_output=True,
                                text=True, timeout=20)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)

    def test_real_child_crash_after_reservation_preserves_uncertain_and_blocks_new_id(self):
        self.initialize()
        req = self.request('ingest', dict(files=[self.source()]))
        self.crash('reserve', req)
        original = self.receipts(req['operation_id'], expected=3)
        self.assertEqual(original['state'], 'uncertain')
        self.assertEqual(original['stages']['staging'], 'not_observed')
        self.assertEqual(self.cli(req, expected=3), original)
        self.assert_code(dict(req, operation_id='new-id'), 'uncertain_previous')
        self.no_artifact_files()
        next_result = self.cli(self.request('ingest', dict(files=[self.source(1)])))
        self.assertEqual(next_result['artifacts'][0]['id'], 'a000002')

    def test_real_child_crash_after_file_and_before_terminal_never_recopies(self):
        self.initialize()
        for phase, expected_files in (('write', 1), ('finish', 3)):
            req = self.request('ingest', dict(files=[self.source(0), self.source(1)]))
            if phase == 'finish':
                # Distinct fingerprint: the earlier partial effect is still uncertain.
                req['payload']['files'].reverse()
            self.crash(phase, req)
            result = self.receipts(req['operation_id'], expected=3)
            self.assertEqual(result['state'], 'uncertain')
            self.assertEqual(len(list(self.store.glob('a*.png'))), expected_files)
            inodes = {p.name: p.stat().st_ino for p in self.store.glob('a*.png')}
            self.assertEqual(self.cli(req, expected=3), result)
            self.assertEqual({p.name: p.stat().st_ino for p in self.store.glob('a*.png')}, inodes)

    def test_reservation_failure_and_all_three_quotas_have_no_image_effect(self):
        self.initialize()
        request = self.request('ingest', dict(files=[self.source(0), self.source(1)]))
        with mock.patch.object(agent, 'reserve', side_effect=OSError('fixture disk refusal')):
            with self.assertRaises(OSError):
                agent.run_request(str(self.store), request)
        self.no_artifact_files()
        self.receipts(request['operation_id'], expected=2)
        for name, cap in (('MAX_ARTIFACTS', 1), ('MAX_BYTES', len(self.images[0]) - 1),
                          ('MAX_OPERATIONS', 1)):
            with mock.patch.object(agent, name, cap):
                with self.assertRaises(agent.AgentError) as error:
                    agent.run_request(str(self.store), request)
                self.assertEqual(error.exception.code, 'quota_exhausted')
            self.no_artifact_files()
        first = self.cli(request)
        self.assertEqual(first['artifacts'][0]['id'], 'a000001')

    def test_batch_bounds_reject_before_more_image_allocation(self):
        self.initialize()
        req = self.request('ingest', dict(files=[self.source(0), self.source(1)]))
        with mock.patch.object(agent, 'MAX_BATCH', len(self.images[0])):
            with self.assertRaises(agent.AgentError) as error:
                agent.run_request(str(self.store), req)
            self.assertEqual(error.exception.code, 'too_large')
        self.no_artifact_files()
        metas = self.ingest()['artifacts']
        req = self.request('pack', dict(artifact_ids=[m['id'] for m in metas],
                           destination=dict(root='iteration', path='oversize.json')))
        with mock.patch.object(agent, 'MAX_BATCH', len(self.images[0])):
            with self.assertRaises(agent.AgentError) as error:
                agent.run_request(str(self.store), req)
            self.assertEqual(error.exception.code, 'too_large')
        self.assertFalse((Path(self.exports['iteration']['path']) / 'oversize.json').exists())

    def test_failed_terminal_commit_keeps_uncertainty_even_if_database_fails(self):
        self.initialize()
        errors = (OSError('fixture ledger unavailable'), KeyError('fixture unexpected failure'),
                  MemoryError('fixture allocation refusal'))
        for i, error in enumerate(errors):
            request = self.request('ingest', dict(files=[self.source(i % 2)]),
                                   kind='claude' if i == 2 else 'codex')
            with mock.patch.object(agent, 'finish', side_effect=error):
                result = agent.run_request(str(self.store), request)
            self.assertEqual(result['state'], 'uncertain')
            self.assertEqual(result['stages']['staging'], 'not_observed')
            self.assertEqual(len(list(self.store.glob('a*.png'))), i + 1)
            self.assertEqual(self.receipts(request['operation_id'], expected=3), result)

    def test_parent_renamed_during_export_is_not_reported_as_delivery(self):
        self.initialize()
        meta = self.ingest()['artifacts'][0]
        dest = Path(self.exports['proposal']['path'])
        (dest / 'child').mkdir(mode=0o700)
        req = self.request('promote', dict(artifact_id=meta['id'], purpose='proposal',
                           destination=dict(root='proposal', path='child/evidence.png')))
        old_write = agent.write_file
        def moved(parent, name, data):
            old_write(parent, name, data)
            (dest / 'child').rename(dest / 'moved')
            (dest / 'child').mkdir(mode=0o700)
        with mock.patch.object(agent, 'write_file', moved):
            result = agent.run_request(str(self.store), req)
        self.assertEqual(result['state'], 'uncertain')
        self.assertEqual(result['stages']['delivery'], 'not_observed')
        self.assertFalse((dest / 'child/evidence.png').exists())
        self.assertEqual((dest / 'moved/evidence.png').read_bytes(), self.images[0])

    def test_tampered_or_missing_artifact_cannot_be_used(self):
        self.initialize()
        imported = self.ingest()
        a = imported['artifacts'][0]
        req = self.request('inspect', dict(artifact_id=a['id']))
        Path(a['path']).write_bytes(self.images[1])
        self.assert_code(req, 'readback_mismatch')
        Path(a['path']).unlink()
        self.cli(req, expected=2)
        self.assert_code(self.request('inspect', dict(artifact_id='a999999')), 'unknown_artifact')

    def test_export_no_overwrite_wrong_purpose_parent_symlink_and_replay_drift(self):
        self.initialize()
        meta = self.ingest()['artifacts'][0]
        def promotion(path, purpose='proposal'):
            return self.request('promote', dict(artifact_id=meta['id'], purpose=purpose,
                                destination=dict(root='proposal', path=path)))
        self.assert_code(promotion('bad.png', 'repo-asset'), 'wrong_purpose')
        self.assert_code(promotion('../bad.png'), 'unsafe_path')
        self.assert_code(promotion('bad.jpg'), 'wrong_extension')
        outside = self.base / 'outside-export'; outside.mkdir(mode=0o700)
        dest = Path(self.exports['proposal']['path'])
        os.symlink(outside, dest / 'alias')
        self.cli(promotion('alias/bad.png'), expected=2)
        self.assertEqual(list(outside.iterdir()), [])
        req = promotion('chosen.png')
        result = self.cli(req)
        target = Path(result['destination_path'])
        inode = target.stat().st_ino
        self.assertEqual(self.cli(req), result)
        self.assertEqual(target.stat().st_ino, inode)
        self.assert_code(promotion('chosen.png'), 'destination_exists')
        target.write_bytes(self.images[1])
        self.assert_code(req, 'readback_mismatch')
        self.assertEqual(self.receipts(req['operation_id']), result)
        dest.rename(self.base / 'original-proposal')
        dest.mkdir(mode=0o700)
        self.assert_code(promotion('new.png'), 'root_changed')
        self.assertEqual(list(dest.iterdir()), [])

    def test_export_crash_and_partial_write_failure_are_truthfully_uncertain(self):
        self.initialize()
        meta = self.ingest()['artifacts'][0]
        req = self.request('promote', dict(artifact_id=meta['id'], purpose='proposal',
                           destination=dict(root='proposal', path='partial.png')))
        self.crash('write', req)
        result = self.receipts(req['operation_id'], expected=3)
        self.assertEqual(result['stages']['delivery'], 'not_observed')
        dest = Path(self.exports['proposal']['path']) / 'partial.png'
        self.assertEqual(dest.read_bytes(), self.images[0])
        self.assert_code(dict(req, operation_id='repeat-with-new-id'), 'uncertain_previous')
        req = self.request('promote', dict(artifact_id=meta['id'], purpose='proposal',
                           destination=dict(root='proposal', path='io-failure.png')))
        old_write = agent.os.write
        def partial(fd, data):
            old_write(fd, data[:4])
            raise OSError('fixture interrupted write')
        with mock.patch.object(agent.os, 'write', partial):
            result = agent.run_request(str(self.store), req)
        self.assertEqual(result['state'], 'uncertain')
        self.assertEqual((Path(self.exports['proposal']['path']) / 'io-failure.png').read_bytes(),
                         self.images[0][:4])

    def test_completed_export_replay_verifies_bytes_after_user_mode_change(self):
        self.initialize()
        meta = self.ingest()['artifacts'][0]
        requests = [self.request('promote', dict(artifact_id=meta['id'], purpose='repo-asset',
                    destination=dict(root='repo-asset', path='asset.png'))),
                    self.request('pack', dict(artifact_ids=[meta['id']],
                    destination=dict(root='iteration', path='bundle.json')))]
        for request in requests:
            result = self.cli(request)
            target = Path(result['destination_path'])
            target.chmod(0o644)
            inode = target.stat().st_ino
            self.assertEqual(self.cli(request), result)
            self.assertEqual(target.stat().st_ino, inode)
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_bundle_corruptions_are_all_validated_before_image_storage(self):
        self.initialize()
        metas = self.ingest()['artifacts']
        pack = self.cli(self.request('pack', dict(artifact_ids=[m['id'] for m in metas],
                        destination=dict(root='iteration', path='transport.json'))))
        path = Path(pack['destination_path'])
        valid = json.loads(path.read_bytes())
        mutations = [lambda x: x.update(schema=2), lambda x: x.update(extra=1),
                     lambda x: x['sender'].update(extra=1), lambda x: x['images'].reverse(),
                     lambda x: x['images'][1].update(data='!' * len(x['images'][1]['data'])),
                     lambda x: x['images'][1].update(sha256='0' * 64),
                     lambda x: x['images'][1].update(size=agent.MAX_IMAGE + 1),
                     lambda x: x['images'][1].update(kind='jpg'),
                     lambda x: x['images'][1].update(source_id=x['images'][0]['source_id']),
                     lambda x: x['images'][1].update(extra=1)]
        receiver = self.base / 'destination-store'
        self.cli(self.init_request(task='receiver-task'), receiver)
        for mutate in mutations:
            data = copy.deepcopy(valid); mutate(data)
            raw = json.dumps(data).encode()
            path.write_bytes(raw)
            req = self.request('unpack', dict(source=dict(root='transport', path=path.name,
                               sha256=sha(raw))), task='receiver-task')
            self.cli(req, receiver, expected=2)
            self.assertEqual(list(receiver.glob('a*.*')), [])
        for raw in (b'{"schema":1', b'{"schema":1,"schema":1}', b'not-json'):
            path.write_bytes(raw)
            self.cli(self.request('unpack', dict(source=dict(root='transport', path=path.name,
                     sha256=sha(raw))), task='receiver-task'), receiver, expected=2)
            self.assertEqual(list(receiver.glob('a*.*')), [])

    def test_feedback_binding_and_fixed_enums(self):
        self.initialize()
        meta = self.ingest()['artifacts'][0]
        base = dict(subject=dict(artifact_id=meta['id']), finding='Fixture finding.', verdict='note')
        for verdict in agent.VERDICTS:
            result = self.cli(self.request('feedback', dict(base, verdict=verdict)))
            self.assertEqual(result['feedback']['bound']['sha256'], meta['sha256'])
        for change in (dict(verdict='learned'), dict(finding='x' * 8193), dict(spec_sha256='bad'),
                       dict(subject=dict(artifact_id=meta['id'], pair_operation_id='other')),
                       dict(subject=dict(pair_operation_id='unknown'))):
            self.cli(self.request('feedback', dict(base, **change)), expected=2)

    def test_doctor_is_explicitly_offline_and_not_managed_retention(self):
        reply = subprocess.run([sys.executable, '-I', '-B', str(CLI), 'doctor'],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(reply.returncode, 0)
        result = json.loads(reply.stdout)
        self.assertEqual(result['capture'], 'not_delivered')
        self.assertFalse(result['retention']['automatic_cleanup'])
        self.assertFalse(result['retention']['deletes_artifacts_or_exports'])
        self.assertFalse(result['drvfs_identity_qualified'])
        self.assertFalse(result['full_image_decode'])
        self.assertFalse(self.store.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
