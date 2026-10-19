#!/usr/bin/env python3
"""Offline checks for codex-drop. Integration flags use disposable resources only.

CODEX_DROP_SSH=1: two real loopback SSH hops, temporary keys/config/known_hosts.
CODEX_DROP_PS=1: Windows PowerShell 5.1 parse and hidden WinForms event/data checks.
CODEX_DROP_NATIVE=/absolute/raw/codex: isolated resumed native TUI, zero model POSTs.
"""
import base64
import getpass
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import uuid
import zlib
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'bin/codex-drop'
TEMPLATE = ROOT / 'share/codex-drop/CodexDrop.ps1'
loader = importlib.machinery.SourceFileLoader('codex_drop', str(BIN))
spec = importlib.util.spec_from_loader(loader.name, loader)
app = importlib.util.module_from_spec(spec)
loader.exec_module(app)
THREAD = '10000000-0000-4000-8000-000000000001'
TARGET = dict(thread=THREAD, socket='fixture', pane='%1', pane_pid=100,
              window='@1', tui_pid=101, tui_start='12345', session='fixture', window_name='Test')


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


PNG = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
       + chunk(b'IDAT', zlib.compress(b'\0\xff\0\0')) + chunk(b'IEND', b''))


def image(data=PNG, name='saved screenshot.png'):
    return dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                data=base64.b64encode(data).decode('ascii'))


def request(op='upload', **kwargs):
    return dict(version=1, op=op, thread=THREAD, socket='fixture',
                target_token=app.target_token(TARGET), images=[image()], **kwargs)


def wait_until(predicate, seconds=10):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError('fixture condition did not become ready')


class ProtocolTests(unittest.TestCase):
    def test_fragmented_frame_round_trip(self):
        class Fragmented(io.BytesIO):
            def read(self, count=-1):
                return super().read(min(count, 3))
        data = request()
        self.assertEqual(app.decode_request(app.read_frame(Fragmented(app.encode_request(data)))), data)

    def test_truncation_empty_oversize_and_malformed(self):
        for data in (b'', b'\0\0', struct.pack('>I', 10) + b'{}', b'\0\0\0\0',
                     struct.pack('>I', app.MAX_REQUEST + 1)):
            with self.subTest(data=data), self.assertRaises(app.DropError):
                app.read_frame(io.BytesIO(data))
        for data in (b'[]', b'null', b'{', b'\xff'):
            with self.subTest(data=data), self.assertRaises(app.DropError):
                app.decode_request(data)

    def test_image_limits_hash_magic_and_encoding(self):
        good = image()
        self.assertEqual(app.validate_images([good])[0]['data'], PNG)
        cases = [[], [None], [dict(good, size=True)], [dict(good, size=0)],
                 [dict(good, size=app.MAX_IMAGE + 1)], [dict(good, data='!')],
                 [dict(good, data='!' * len(good['data']))], [dict(good, sha256='0' * 64)],
                 [image(b'not a screenshot')], [good] * 11]
        for items in cases:
            with self.subTest(items=str(items)[:70]), self.assertRaises(app.DropError):
                app.validate_images(items)
        with mock.patch.object(app, 'MAX_BATCH', len(PNG)):
            with self.assertRaises(app.DropError):
                app.validate_images([good, good])

    def test_invalid_upload_never_opens_ssh_or_store(self):
        data = request(); data['images'] = [image(b'not an image')]
        with mock.patch.object(app, 'call_receiver') as ssh, mock.patch.object(app, 'store_images') as store:
            with self.assertRaises(app.DropError):
                app.handle_client(data)
            with self.assertRaises(app.DropError):
                app.handle_receive(data)
            ssh.assert_not_called(); store.assert_not_called()

    def test_aliases_and_target_tokens_reject_injection(self):
        for value in ('-oProxyCommand=bad', 'home;true', 'x\ntrue', 'home/user'):
            with self.assertRaises(app.DropError):
                app.require_host(value)
        for value in ('', '%%%', app.target_token(dict(TARGET, socket='another'))):
            with self.assertRaises(app.DropError):
                app.parse_token(value, THREAD, 'fixture')
        argv = app.nested_argv('bastion', 'home', app.REMOTE_COMMAND)
        self.assertEqual(argv[0], 'ssh')
        self.assertNotIn('-J', argv)
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('BatchMode=yes', argv)
        self.assertIn('PermitLocalCommand=no', argv)

    def test_transport_bounds_and_timeout(self):
        code, out, _, timeout, overflow = app.run_bounded(
            [sys.executable, '-c', 'print("x"*5000)'], None, 3, 20)
        self.assertEqual(code, 0); self.assertEqual(len(out), 20); self.assertTrue(overflow)
        self.assertFalse(timeout)
        result = app.run_bounded([sys.executable, '-c', 'import time;time.sleep(10)'], None, .1, 20)
        self.assertTrue(result[3])

    def test_uncertain_timeout_is_explicit(self):
        with mock.patch.object(app, 'run_bounded', return_value=(-9, b'', b'', True, False)):
            with self.assertRaises(app.DropError) as caught:
                app.call_receiver('bastion', 'home', b'x', .1)
        self.assertEqual(caught.exception.code, 'timeout')


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='codex-drop-store-')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, HOME=str(self.home)); self.env.start()
        self.addCleanup(self.env.stop)
        self.base = self.home.joinpath(*app.STORE_PARTS)

    def test_private_persistence_hash_and_safe_names(self):
        files = app.store_images(app.validate_images([image(name='$(touch SENTINEL)\nodd.png'), image()]))
        for item in files:
            path = Path(item['path'])
            self.assertEqual(path.read_bytes(), PNG)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertRegex(str(path), app.SAFE_PATH_RE)
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.home / 'SENTINEL').exists())

    def test_symlink_and_shared_directory_refused_without_change(self):
        other = self.home / 'other'; other.mkdir()
        (self.home / '.local').symlink_to(other, target_is_directory=True)
        with self.assertRaises(app.DropError):
            app.store_images(app.validate_images([image()]))
        self.assertEqual(list(other.iterdir()), [])
        (self.home / '.local').unlink()
        self.base.mkdir(parents=True, mode=0o755)
        with self.assertRaises(app.DropError):
            app.store_images(app.validate_images([image()]))
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o755)

    def test_collision_preserves_existing_and_partial_failure_cleans_up(self):
        with mock.patch.object(app.secrets, 'token_hex', return_value='abc'), \
                mock.patch.object(app.time, 'strftime', return_value='fixed'):
            first = app.store_images(app.validate_images([image()]))
            with self.assertRaises(FileExistsError):
                app.store_images(app.validate_images([image()]))
        self.assertEqual(Path(first[0]['path']).read_bytes(), PNG)
        with mock.patch.object(app, 'readback', side_effect=app.DropError('readback_mismatch', 'fixture')):
            with self.assertRaises(app.DropError):
                app.store_images(app.validate_images([image()]))
        self.assertEqual(len(list(self.base.iterdir())), 1)

    def test_file_open_is_exclusive_and_refuses_links(self):
        seen = []
        original = os.open
        def record(path, flags, *args, **kwargs):
            if flags & os.O_CREAT:
                seen.append(flags)
            return original(path, flags, *args, **kwargs)
        with mock.patch.object(app.os, 'open', side_effect=record):
            app.store_images(app.validate_images([image()]))
        self.assertTrue(seen)
        self.assertTrue(all(flags & os.O_EXCL and flags & os.O_NOFOLLOW for flags in seen))


class TargetTests(unittest.TestCase):
    @staticmethod
    def pane_row(**changes):
        values = dict(pane='%1', pid='100', mode='0', window='@1', tty='/dev/pts/9',
                      thread=THREAD, session='first', name='Chat')
        values.update(changes)
        return '\t'.join(values[k] for k in ('pane', 'pid', 'mode', 'window', 'tty', 'thread', 'session', 'name'))

    def test_linked_rows_resolve_one_physical_target_with_same_token(self):
        first = self.pane_row()
        for changes in (dict(session='second'), dict(name='Renamed'), dict(session='second', name='Renamed')):
            tokens = []
            second = self.pane_row(**changes)
            for rows in ((first, second), (second, first)):
                with self.subTest(changes=changes, first=rows[0]), \
                        mock.patch.object(app, 'tmux', return_value='\n'.join(rows)), \
                        mock.patch.object(app.os, 'stat', return_value=SimpleNamespace(st_rdev=1)), \
                        mock.patch.object(app, 'children_map', return_value={}), \
                        mock.patch.object(app, 'find_tui', return_value=(101, '12345')):
                    try:
                        target, mode = app.discover_target(THREAD, 'fixture')
                    except app.DropError as error:
                        self.fail('linked rows incorrectly refused: ' + error.code)
                    self.assertEqual(target['pane'], '%1'); self.assertEqual(mode, '0')
                    self.assertEqual(target['session'], rows[0].split('\t')[6])
                    tokens.append(app.target_token(target))
            if len(tokens) == 2:
                self.assertEqual(tokens[0], tokens[1], 'presentation order changed confirmed identity')

    def test_distinct_physical_panes_remain_ambiguous(self):
        rows = [self.pane_row(), self.pane_row(pane='%2', pid='200', tty='/dev/pts/10')]
        with mock.patch.object(app, 'tmux', return_value='\n'.join(rows)):
            with self.assertRaises(app.DropError) as caught:
                app.discover_target(THREAD, 'fixture')
        self.assertEqual(caught.exception.code, 'target_ambiguous')

    def test_conflicting_physical_fields_remain_ambiguous(self):
        for field, value in dict(pane='%2', pid='200', mode='1', window='@2', tty='/dev/pts/10').items():
            rows = [self.pane_row(), self.pane_row(**{field: value})]
            with self.subTest(field=field), mock.patch.object(app, 'tmux', return_value='\n'.join(rows)):
                with self.assertRaises(app.DropError) as caught:
                    app.discover_target(THREAD, 'fixture')
                self.assertEqual(caught.exception.code, 'target_ambiguous')

    def test_changed_identity_copy_mode_shell_and_modal_refusals(self):
        for key in app.IDENTITY_KEYS:
            changed = dict(TARGET)
            changed[key] = changed[key] + 1 if isinstance(changed[key], int) else changed[key] + 'x'
            with self.subTest(key=key), mock.patch.object(app, 'discover_target', return_value=(changed, '0')):
                with self.assertRaises(app.DropError) as caught:
                    app.check_ready(TARGET)
                self.assertEqual(caught.exception.code, 'target_changed')
        with mock.patch.object(app, 'discover_target', return_value=(TARGET, '1')):
            with self.assertRaises(app.DropError):
                app.check_ready(TARGET)
        for lines, cursor in [(['$ bash'], 0), (['Would you like to run this command?', '› 1. Yes'], 1),
                              (['› draft', 'outside'], 30)]:
            with self.assertRaises(app.DropError):
                app.composer_ready(lines, cursor)
        app.composer_ready(['conversation', '› my existing draft', ''], 1)

    def test_paste_uses_private_buffer_and_never_enter(self):
        with mock.patch.object(app, 'tmux', return_value='') as tmux:
            app.paste_path('fixture', '%1', '/tmp/private/image.png')
        calls = [c.args for c in tmux.call_args_list]
        self.assertEqual(calls[0][1], 'load-buffer')
        self.assertEqual(calls[1][1], 'paste-buffer')
        self.assertIn('-p', calls[1]); self.assertIn('-d', calls[1])
        self.assertFalse(any('send-keys' in c or 'Enter' in c for c in calls))
        self.assertEqual(tmux.call_args_list[0].kwargs['data'], b'/tmp/private/image.png')

    def test_transfer_is_distinct_from_unverified_or_verified_attachment(self):
        for verified in (False, True):
            files = [dict(path='/tmp/private/image.png', attach='not-attempted')]
            with mock.patch.object(app, 'store_images', return_value=files), \
                    mock.patch.object(app, 'check_ready', return_value=(TARGET, ['› saved draft'])), \
                    mock.patch.object(app, 'paste_path') as paste, \
                    mock.patch.object(app, 'wait_for_new_mark', return_value=verified):
                reply = app.handle_upload(request(), THREAD, 'fixture')
            self.assertTrue(reply['ok']); paste.assert_called_once()
            self.assertEqual(reply['attach']['state'], 'verified' if verified else 'unverified')
            self.assertEqual(reply['status'], 'transferred+attached-verified' if verified else 'transferred')


class BundleTests(unittest.TestCase):
    def test_deterministic_ascii_bundle_embeds_exact_source_and_config(self):
        cfg = dict(version=1, thread=THREAD, socket='fixture', bastion='bastion', home='home')
        one = app.build_bundle(TEMPLATE.read_bytes(), BIN.read_bytes(), cfg)
        two = app.build_bundle(TEMPLATE.read_bytes(), BIN.read_bytes(), cfg)
        self.assertEqual(one, two); one.decode('ascii')
        self.assertIn(base64.b64encode(BIN.read_bytes()), one)
        self.assertNotIn(app.CLIENT_PLACEHOLDER.encode(), one)
        text = app.bootstrap_text(hashlib.sha256(one).hexdigest(), 'bastion', 'home', '/tmp/fixture.ps1')
        self.assertIn('CreateNew', text); self.assertIn('ReparsePoint', text)
        self.assertIn('Different $file exists; not replaced', text)
        self.assertNotIn('Set-Clipboard', text); self.assertNotIn('Set-ExecutionPolicy', text)


@unittest.skipUnless(os.environ.get('CODEX_DROP_PS') == '1', 'set CODEX_DROP_PS=1 for Windows PS5.1')
class PowerShellTests(unittest.TestCase):
    def run_hidden_case(self, body):
        cfg = dict(version=1, thread=THREAD, socket='fixture', bastion='bastion', home='home')
        with tempfile.TemporaryDirectory(prefix='codex-drop-ps-case-') as directory:
            root = Path(directory)
            (root / 'bundle.ps1').write_bytes(app.build_bundle(TEMPLATE.read_bytes(), BIN.read_bytes(), cfg))
            (root / 'image.png').write_bytes(PNG)
            def win(path):
                return subprocess.check_output(['wslpath', '-w', str(path)], text=True).strip().replace("'", "''")
            prefix = PS_TEST[:PS_TEST.index('function Start-Client(')]
            script = prefix + r'''
$script:TransportCount = 0
function Start-Client($Payload, $Label, $TimeoutSeconds, $OnDone, $Context) {
  $script:TransportCount++
  $Payload.Dispose()
}
try {
  $script:ConfirmedToken = 'fixture-token'
''' + body + r'''
} finally { $timer.Stop(); $form.Dispose() }
'''
            script = (script.replace('@@BUNDLE@@', win(root / 'bundle.ps1'))
                      .replace('@@TEMPLATE@@', win(TEMPLATE)).replace('@@IMAGE@@', win(root / 'image.png'))
                      .replace('@@PNG@@', base64.b64encode(PNG).decode()))
            (root / 'test.ps1').write_text(script, encoding='ascii')
            return subprocess.run(['powershell.exe', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass',
                                   '-File', win(root / 'test.ps1')], capture_output=True, text=True, timeout=45)

    def test_gui_timeout_discards_success_and_retains_queue(self):
        result = self.run_hidden_case(r'''
  Add-QueueFile '@@IMAGE@@'
  $checkAuto.Checked = $true
  $reply = @{ok=$true; status='transferred+attached-verified'; files=@(
    @{name='image.png';size=69;sha256=('a'*64);attach='attached-verified'})} | ConvertTo-Json -Depth 5 -Compress
  $fixtureJob = @{Out=[pscustomobject]@{Result=$reply}; Err=[pscustomobject]@{Result=''}
    Payload=[IO.MemoryStream]::new(); TimedOut=$true; Process=[pscustomobject]@{HasExited=$true}
    Context=@($script:Queue[0]); OnDone={param($Reply,$ErrText,$Context) Complete-Upload $Reply $ErrText $Context}}
  Complete-Job $fixtureJob
  if ($checkAuto.Checked) { throw 'BUG: GUI timeout kept automatic sending enabled' }
  if ($script:Queue.Count -ne 1) { throw 'BUG: GUI timeout accepted late success and lost queued files' }
  if (-not $buttonSend.Enabled) { throw 'explicit Send queued should remain available' }
  if ($statusBox.Text.Contains('DONE:')) { throw 'BUG: GUI timeout displayed false success' }
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_grown_oversize_queue_refused_before_large_allocation(self):
        result = self.run_hidden_case(r'''
  [AppDomain]::MonitoringIsEnabled = $true
  $path = Join-Path $env:TEMP ('codex-drop-growth-' + [guid]::NewGuid().ToString('N') + '.png')
  try {
    [IO.File]::WriteAllBytes($path, [Convert]::FromBase64String('@@PNG@@'))
    Add-QueueFile $path
    if ($script:Queue.Count -ne 1) { throw 'fixture image was not queued' }
    $writer = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $writer.SetLength(128MB) } finally { $writer.Dispose() }
    $before = [AppDomain]::CurrentDomain.MonitoringTotalAllocatedMemorySize
    Start-Upload
    $allocated = [AppDomain]::CurrentDomain.MonitoringTotalAllocatedMemorySize - $before
    Write-Output ('ALLOCATED_BYTES=' + $allocated)
    if ($script:TransportCount -ne 0) { throw 'oversized image reached transport' }
    if ($script:Queue.Count -ne 0 -or -not $statusBox.Text.Contains('25 MiB limit')) {
      throw 'oversized file was not refused with an explicit size-limit status'
    }
    if ($allocated -ge 64MB) { throw ('BUG: oversized queued image read before limit, allocated ' + $allocated) }
  } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ALLOCATED_BYTES=', result.stdout)
        print(result.stdout.strip())

    def test_timer_timeout_disables_automatic_sending_immediately(self):
        result = self.run_hidden_case(r'''
  Add-QueueFile '@@IMAGE@@'
  $checkAuto.Checked = $true
  $fixtureProcess = [pscustomobject]@{HasExited=$false; Killed=$false}
  $fixtureProcess | Add-Member ScriptMethod Kill { $this.Killed = $true }
  $script:Job = @{Process=$fixtureProcess;Out=[pscustomobject]@{IsCompleted=$false}
    Err=[pscustomobject]@{IsCompleted=$false};InputClosed=$true;TimedOut=$false
    Deadline=(Get-Date).AddSeconds(-1)}
  $flags = [Reflection.BindingFlags]'Instance,NonPublic'
  [void]$timer.GetType().GetMethod('OnTick', $flags).Invoke($timer, [object[]]@([EventArgs]::Empty))
  if ($checkAuto.Checked -or -not $script:Job.TimedOut -or -not $fixtureProcess.Killed) {
    throw 'GUI timer failed to stop automatic sending on timeout'
  }
  if ($script:Queue.Count -ne 1) { throw 'GUI timer changed queued files' }
  $script:Job = $null
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_bootstrap_hash_idempotence_and_existing_file_refusal(self):
        # Keep the bootstrap's real verification/write logic. Substitute only its
        # SSH fetch and GUI launch, so this cannot contact a host or show a form.
        data = b'fixture: not an executable client bundle'
        bootstrap = app.bootstrap_text(hashlib.sha256(data).hexdigest(), 'bastion', 'home', '/tmp/fixture.ps1')
        fetch_at = bootstrap.index('$psi = ')
        bytes_at = bootstrap.index('$bytes = ')
        bootstrap = (bootstrap[:fetch_at] + "$out = [pscustomobject]@{Result='" +
                     base64.b64encode(data).decode() + "'}\n" + bootstrap[bytes_at:])
        with tempfile.TemporaryDirectory(prefix='codex-drop-bootstrap-') as directory:
            root = Path(directory)
            win = subprocess.check_output(['wslpath', '-w', str(root)], text=True).strip().replace("'", "''")
            script = ("$ErrorActionPreference='Stop'\n$env:LOCALAPPDATA='" + win + "'\n" +
                      "function Start-Process { $script:Launched=$true }\n" +
                      "$setup = [scriptblock]::Create(@'\n" + bootstrap + "\n'@)\n" + r'''
$script:Launched=$false
& $setup
if (-not $script:Launched) { throw 'first setup did not reach launch' }
$path=Join-Path $env:LOCALAPPDATA 'CodexDrop\CodexDrop.ps1'
$before=[IO.File]::ReadAllText($path)
& $setup
if ([IO.File]::ReadAllText($path) -ne $before) { throw 'repeat setup changed same file' }
[IO.File]::WriteAllText($path, 'PRESERVE_EXISTING')
$script:Launched=$false; $refused=$false
try { & $setup } catch { $refused=$true }
if (-not $refused -or $script:Launched) { throw 'different existing script was not refused' }
if ([IO.File]::ReadAllText($path) -ne 'PRESERVE_EXISTING') { throw 'existing script overwritten' }
$bad=[scriptblock]::Create($setup.ToString().Replace('@@GOOD@@', ('0' * 64)))
$script:Launched=$false; $refused=$false
try { & $bad } catch { $refused=$_.Exception.Message -like '*hash mismatch*' }
if (-not $refused -or $script:Launched) { throw 'wrong digest was not refused' }
Write-Output 'BOOTSTRAP_HASH_AND_NO_OVERWRITE_PASS'
''')
            script = script.replace('@@GOOD@@', hashlib.sha256(data).hexdigest())
            file = root / 'test.ps1'; file.write_text(script, encoding='ascii')
            result = subprocess.run(['powershell.exe', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass',
                                     '-File', win + '\\test.ps1'], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ast_hidden_file_drop_payload_and_uncertain_retry(self):
        # The form is constructed but never shown. The test replaces transport with
        # a local capture, then invokes the real WinForms drag handlers via reflection.
        cfg = dict(version=1, thread=THREAD, socket='fixture', bastion='bastion', home='home')
        with tempfile.TemporaryDirectory(prefix='codex-drop-ps-') as directory:
            root = Path(directory)
            bundle = app.build_bundle(TEMPLATE.read_bytes(), BIN.read_bytes(), cfg)
            (root / 'bundle.ps1').write_bytes(bundle)
            (root / 'saved screenshot.png').write_bytes(PNG)
            def win(path):
                return subprocess.check_output(['wslpath', '-w', str(path)], text=True).strip().replace("'", "''")
            script = PS_TEST.replace('@@BUNDLE@@', win(root / 'bundle.ps1')) \
                .replace('@@TEMPLATE@@', win(TEMPLATE)).replace('@@IMAGE@@', win(root / 'saved screenshot.png')) \
                .replace('@@PAYLOAD@@', win(root / 'payload.bin'))
            (root / 'test.ps1').write_text(script, encoding='ascii')
            result = subprocess.run(['powershell.exe', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass',
                                     '-File', win(root / 'test.ps1')], capture_output=True, text=True, timeout=40)
            raw = io.BytesIO((root / 'payload.bin').read_bytes())
            self.assertEqual(app.read_frame(raw), BIN.read_bytes())
            req = app.decode_request(app.read_frame(raw))
            self.assertEqual(req['thread'], THREAD)
            self.assertEqual(app.validate_images(req['images'])[0]['data'], PNG)
            self.assertEqual(raw.read(), b'')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


PS_TEST = r'''
$ErrorActionPreference = 'Stop'
foreach ($file in @('@@BUNDLE@@', '@@TEMPLATE@@')) {
  $tokens = $null; $errors = $null
  [void][Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
  if ($errors.Count) { throw ($errors | Out-String) }
}
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'Requires actual Windows PowerShell 5.1' }
$source = [IO.File]::ReadAllText('@@BUNDLE@@')
$run = '[System.Windows.Forms.Application]::Run($form)'
if (-not $source.EndsWith($run + "`n")) { throw 'Unknown entrypoint; refuse to show form' }
. ([scriptblock]::Create($source.Replace($run, '')))
function Start-Client($Payload, $Label, $TimeoutSeconds, $OnDone, $Context) {
  [IO.File]::WriteAllBytes('@@PAYLOAD@@', $Payload.ToArray())
  $Payload.Dispose()
}
try {
  $script:ConfirmedToken = 'fixture-token'
  $data = New-Object Windows.Forms.DataObject
  $data.SetData([Windows.Forms.DataFormats]::FileDrop, [string[]]@('@@IMAGE@@'))
  $event = New-Object Windows.Forms.DragEventArgs($data, 0, 0, 0,
    [Windows.Forms.DragDropEffects]::Copy, [Windows.Forms.DragDropEffects]::None)
  $flags = [Reflection.BindingFlags]'Instance,NonPublic'
  $eventArgs = [object[]]::new(1)
  $eventArgs[0] = $event.PSObject.BaseObject
  [void]$dropLabel.GetType().GetMethod('OnDragEnter', $flags).Invoke($dropLabel, $eventArgs)
  if ($event.Effect -ne [Windows.Forms.DragDropEffects]::Copy) { throw 'FileDrop not accepted' }
  [void]$dropLabel.GetType().GetMethod('OnDragDrop', $flags).Invoke($dropLabel, $eventArgs)
  if (-not [IO.File]::Exists('@@PAYLOAD@@')) { throw 'drop did not build a payload' }
  if ($script:Queue.Count -ne 1) { throw 'queue not retained until receipt' }
  $checkAuto.Checked = $true
  $reply = [pscustomobject]@{ok=$false; error=[pscustomobject]@{code='timeout';message='result uncertain'}}
  Complete-Upload $reply '' @($script:Queue[0])
  if ($checkAuto.Checked) { throw 'BUG: uncertain timeout leaves send-on-drop enabled and can replay queued images' }
  foreach ($code in @('home_auth','bad_target','receiver_failed')) {
    $checkAuto.Checked=$true
    $reply=[pscustomobject]@{ok=$false;error=[pscustomobject]@{code=$code;message='fixture'}}
    Complete-Upload $reply '' @($script:Queue[0])
    if ($checkAuto.Checked -or $script:Queue.Count -ne 1) { throw 'upload failure did not preserve queue and stop auto-send' }
  }
  Write-Output 'PS51_AST_AND_HIDDEN_DROP_PASS'
} finally { $timer.Stop(); $form.Dispose() }
'''


@unittest.skipUnless(os.environ.get('CODEX_DROP_SSH') == '1', 'set CODEX_DROP_SSH=1 for two-hop sshd')
class TwoHopTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which('sshd'):
            self.skipTest('OpenSSH server required')
        self.temp = tempfile.TemporaryDirectory(prefix='codex-drop-twohop-')
        self.root = Path(self.temp.name); self.processes = []
        self.addCleanup(self.cleanup)
        self.home = self.root / 'home'; self.home.mkdir()
        for name in ('host_bastion', 'host_home', 'client'):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.root / name)], check=True)
        self.config = self.root / 'ssh_config'; self.known = self.root / 'known_hosts'
        self.known.write_text('')
        runner = self.root / 'remote.py'
        runner.write_text('import os,sys,shlex\n'
                          f'os.environ["HOME"]={str(self.home)!r}\n'
                          'command=os.environ.get("SSH_ORIGINAL_COMMAND", "exit 0")\n'
                          f'if command=={app.REMOTE_COMMAND!r}: command=shlex.join([sys.executable,{str(BIN)!r},"receive"])\n'
                          'os.execv("/bin/sh",["sh","-c",command])\n')
        entries = []
        for alias in ('bastion', 'home'):
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
            cfg = self.root / ('sshd_' + alias)
            # The disposable Bastion substitutes its own ssh -F only. No real
            # user SSH config or credentials are read or changed at either hop.
            command = f'{sys.executable} {runner}'
            if alias == 'bastion':
                jump = self.root / 'jump.py'
                jump.write_text('import os,shlex\ncmd=shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND","true"))\n'
                                f'if cmd and cmd[0]=="ssh": cmd[1:1]=["-F",{str(self.config)!r}]\n'
                                'os.execvp(cmd[0],cmd)\n')
                command = f'{sys.executable} {jump}'
            cfg.write_text(f'''Port {port}
ListenAddress 127.0.0.1
HostKey {self.root / ('host_' + alias)}
PidFile {self.root / (alias + '.pid')}
AuthorizedKeysFile {self.root / 'client.pub'}
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PermitRootLogin no
AllowUsers {getpass.getuser()}
LogLevel ERROR
ForceCommand {command}
''')
            log = self.root / (alias + '.log')
            daemon = subprocess.Popen([shutil.which('sshd'), '-D', '-f', str(cfg), '-E', str(log)])
            self.processes.append(daemon)
            def ready():
                if daemon.poll() is not None:
                    self.fail(log.read_text())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        return True
                except OSError:
                    return False
            wait_until(ready, 5)
            public = (self.root / ('host_' + alias + '.pub')).read_text().split()
            with self.known.open('a') as out:
                out.write(f'[127.0.0.1]:{port} ' + ' '.join(public[:2]) + '\n')
            entries.append(f'''Host {alias}
 HostName 127.0.0.1
 Port {port}
 User {getpass.getuser()}
 IdentityFile {self.root / 'client'}
 IdentitiesOnly yes
 UserKnownHostsFile {self.known}
 GlobalKnownHostsFile /dev/null
 LogLevel ERROR
''')
        self.config.write_text('\n'.join(entries))
        self.options = mock.patch.object(app, 'SSH_OPTIONS', ('-F', str(self.config), *app.SSH_OPTIONS))
        self.options.start(); self.addCleanup(self.options.stop)

    def cleanup(self):
        for daemon in reversed(self.processes):
            if daemon.poll() is None:
                daemon.terminate(); daemon.wait(timeout=5)
        self.temp.cleanup()

    def test_actual_nested_transfer_and_hop_error_classification(self):
        app.probe_route('bastion', 'home')
        req = request(attach=False)
        reply = app.handle_client(req)
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(reply['route'], 'bastion > home')
        saved = Path(reply['files'][0]['path'])
        self.assertTrue(saved.is_relative_to(self.home)); self.assertEqual(saved.read_bytes(), PNG)
        # Remove home host-key trust in fixture only, keeping Bastion trusted.
        lines = self.known.read_text().splitlines(); self.known.write_text(lines[0] + '\n')
        with self.assertRaises(app.DropError) as caught:
            app.probe_route('bastion', 'home')
        self.assertEqual(caught.exception.code, 'home_hostkey')
        self.known.write_text('')
        with self.assertRaises(app.DropError) as caught:
            app.probe_route('bastion', 'home')
        self.assertEqual(caught.exception.code, 'bastion_hostkey')
        self.known.write_text('\n'.join(lines) + '\n')
        wrong = self.root / 'wrong_client'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(wrong)], check=True)
        original = self.config.read_text()
        head, tail = original.split('Host home\n')
        self.config.write_text(head + 'Host home\n' + tail.replace(str(self.root / 'client'), str(wrong)))
        with self.assertRaises(app.DropError) as caught:
            app.probe_route('bastion', 'home')
        self.assertEqual(caught.exception.code, 'home_auth')
        self.config.write_text(original.replace(str(self.root / 'client'), str(wrong)))
        with self.assertRaises(app.DropError) as caught:
            app.probe_route('bastion', 'home')
        self.assertEqual(caught.exception.code, 'bastion_auth')


@unittest.skipUnless(os.environ.get('CODEX_DROP_NATIVE'), 'set CODEX_DROP_NATIVE to raw Codex binary')
class NativeTests(unittest.TestCase):
    def test_resumed_exact_chat_draft_native_images_copy_restart_and_shell(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        posts = []
        class Stub(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.send_header('Content-Type', 'application/json')
                self.end_headers(); self.wfile.write(b'{"data":[]}')
            def do_POST(self):
                posts.append(self.path); self.send_error(503, 'Fixture forbids model requests')
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Stub)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        temp = tempfile.TemporaryDirectory(prefix='codex-drop-native-'); self.addCleanup(temp.cleanup)
        root = Path(temp.name); home = root / 'home'; ch = home / '.codex'
        sessions = ch / 'sessions/2026/10/16'; sessions.mkdir(parents=True)
        thread = str(uuid.uuid4()); sock = 'drop-native-' + root.name
        config = f'''model="gpt-6.1-sol"
model_provider="fixture"
sandbox_mode="read-only"
approval_policy="never"
[model_providers.fixture]
name="Offline fixture"
base_url="http://127.0.0.1:{server.server_port}/v1"
wire_api="responses"
requires_openai_auth=false
'''
        (ch / 'config.toml').write_text(config)
        meta = dict(id=thread, timestamp='2026-10-16T00:00:00Z', cwd=str(home),
                    originator='codex_cli_rs', cli_version='0.163.0', source='cli', model_provider='fixture')
        (sessions / f'rollout-2026-10-16T00-00-00-{thread}.jsonl').write_text(
            json.dumps(dict(timestamp=meta['timestamp'], type='session_meta', payload=meta)) + '\n')
        command = shlex.join(['env', 'TERM=xterm-256color', 'HOME=' + str(home), 'CODEX_HOME=' + str(ch),
                              os.environ['CODEX_DROP_NATIVE'], '--no-daemon', '--no-alt-screen',
                              '-C', str(home), 'resume', thread])
        def tm(*args, check=True):
            return subprocess.run(['tmux', '-L', sock, *args], text=True, capture_output=True,
                                  timeout=5, check=check).stdout
        self.addCleanup(lambda: tm('kill-server', check=False))
        tm('-f', '/dev/null', 'new-session', '-d', '-x', '120', '-y', '36', '-s', 'fixture', command)
        pane = tm('display-message', '-p', '#{pane_id}').strip()
        # Match Byobu's window marker and real linked-window topology. Listing
        # all sessions must produce two rows for this one physical target.
        tm('set-option', '-w', '-t', pane, '@byobu-codex-thread-id', thread)
        tm('new-session', '-d', '-x', '120', '-y', '36', '-s', 'fixture-linked', 'sleep 300')
        tm('link-window', '-s', 'fixture:0', '-t', 'fixture-linked:1')
        def screen():
            return tm('capture-pane', '-p', '-t', pane)
        wait_until(lambda: 'GPT-6.1-Sol' in screen(), 15)
        rows = [line.split('\t') for line in tm('list-panes', '-a', '-F', app.PANE_FORMAT).splitlines()
                if line.split('\t')[5] == thread]
        self.assertEqual(len(rows), 2); self.assertEqual({row[0] for row in rows}, {pane})
        try:
            target, _ = app.discover_target(thread, sock)
        except app.DropError as error:
            self.fail('real linked native target incorrectly refused: ' + error.code)
        self.assertEqual(target['pane'], pane)
        # Type draft without Enter, then exercise actual bracketed native attachments.
        tm('send-keys', '-t', pane, '-l', 'KEEP_THIS_DRAFT ')
        wait_until(lambda: 'KEEP_THIS_DRAFT' in screen())
        req = dict(version=1, op='upload', thread=thread, socket=sock,
                   target_token=app.target_token(target), images=[image(), image()])
        with mock.patch.dict(os.environ, HOME=str(home)):
            reply = app.handle_upload(req, thread, sock)
            self.assertEqual(reply['status'], 'transferred+attached-verified', reply)
            final = screen()
            self.assertIn('KEEP_THIS_DRAFT', final); self.assertIn('[Image #1]', final)
            self.assertIn('[Image #2]', final); self.assertEqual(posts, [])
            self.assertTrue(all(Path(f['path']).read_bytes() == PNG for f in reply['files']))
            tm('copy-mode', '-t', pane)
            blocked = app.handle_upload(req, thread, sock)
            self.assertEqual(blocked['attach']['state'], 'blocked')
            self.assertEqual(blocked['files'][0]['attach'], 'not-attempted')
            tm('send-keys', '-t', pane, '-X', 'cancel')
            self.assertEqual(app.mark_state(screen().splitlines()), app.mark_state(final.splitlines()))
            tm('respawn-pane', '-k', '-t', pane, command)
            wait_until(lambda: 'GPT-6.1-Sol' in screen(), 15)
            restarted, _ = app.discover_target(thread, sock)
            self.assertNotEqual(target['tui_pid'], restarted['tui_pid'])
            blocked = app.handle_upload(req, thread, sock)
            self.assertEqual(blocked['attach']['code'], 'target_changed')
            tm('respawn-pane', '-k', '-t', pane, 'bash --noprofile --norc')
            wait_until(lambda: tm('display-message', '-p', '-t', pane,
                                 '#{pane_current_command}').strip() == 'bash')
            with self.assertRaises(app.DropError) as caught:
                app.discover_target(thread, sock)
            self.assertEqual(caught.exception.code, 'target_not_codex')
        self.assertEqual(posts, [], 'fixture submitted a model request')


class CatalogRetentionTests(unittest.TestCase):
    def setUp(self):
        guard = mock.patch.object(app, 'tmux', return_value='')
        guard.start(); self.addCleanup(guard.stop)

    def test_global_presence_veto_covers_switched_unlabelled_and_external_processes(self):
        for scenario in ('switched-thread', 'other-process', 'unlabelled', 'outside-socket', 'wrapper'):
            with self.subTest(scenario=scenario), mock.patch.object(app, 'tmux', return_value=''), mock.patch.object(
                    app, 'scan_processes', return_value={'process_complete': True, 'codex_present': True}, create=True):
                result = app.handle_inspect(THREAD, 'default')
                self.assertFalse(result['definite'])

    def test_precise_process_classifier_excludes_own_service_and_shells(self):
        for exe, argv in (
            ('python3', ['python3', '-I', 'codex-drop-web']),
            ('python3', ['python3', '-I', 'codex-drop', 'receive']),
            ('python3', ['python3', 'scan_processes.py']),
            ('bash', ['bash', '/home/user/bin/byobu-codex', 'status']),
            ('bash', ['bash', '-c', 'echo codex']),
        ):
            self.assertFalse(app.codex_process(exe, argv), argv)
        for exe, argv in (('/opt/codex', ['anything']), ('node', ['node', '/opt/codex.js']),
                          ('bash', ['bash', '/opt/codex', 'resume', THREAD]),
                          ('/opt/codex-x86_64-unknown-linux-musl', ['anything'])):
            self.assertTrue(app.codex_process(exe, argv), argv)

    def test_bounded_process_scan_stat_parser_and_unknowns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); proc = root / '123'; proc.mkdir()
            (root / 'self').mkdir(); (root / 'self/mountinfo').write_text('1 0 0:1 / /proc rw - proc proc rw\n')
            (proc / 'status').write_text('Uid:\t' + '\t'.join([str(os.geteuid())] * 4) + '\n')
            fields = ['S'] + ['1'] * 19; fields[19] = '12345'
            (proc / 'stat').write_text('123 (odd ) name with spaces) ' + ' '.join(fields))
            (proc / 'cmdline').write_bytes(b'node\0/opt/codex.js\0resume\0')
            (proc / 'exe').symlink_to('/usr/bin/node')
            result = app.scan_processes(root)
            self.assertTrue(result['process_complete']); self.assertTrue(result['codex_present'])
            self.assertFalse(app.scan_processes(root, max_entries=0)['process_complete'])
            times = iter((0, 3, 4))
            self.assertFalse(app.scan_processes(root, clock=lambda: next(times))['process_complete'])
            with mock.patch('builtins.open', side_effect=PermissionError('fixture')):
                self.assertFalse(app.scan_processes(root)['process_complete'])
            (proc / 'stat').write_text('malformed')
            self.assertFalse(app.scan_processes(root)['process_complete'])

    def test_hardened_same_user_process_uses_status_not_directory_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); proc = root / '123'; proc.mkdir(); (root / 'self').mkdir()
            (root / 'self/mountinfo').write_text('1 0 0:1 / /proc rw - proc proc rw\n')
            (proc / 'status').write_text('Uid:\t' + '\t'.join([str(os.geteuid())] * 4) + '\n')
            fields = ['S'] + ['1'] * 19; fields[19] = '12345'
            (proc / 'stat').write_text('123 (hardened) ' + ' '.join(fields))
            (proc / 'cmdline').write_bytes(b'/opt/codex\0resume\0other-thread\0')
            def info_with_owner(owner):
                values = list(os.stat(proc)); values[4] = owner
                return os.stat_result(values)
            with mock.patch.object(app.os, 'readlink', side_effect=PermissionError('fixture')):
                for owner in (0, 65534):
                    entry = SimpleNamespace(name='123', stat=lambda **_: info_with_owner(owner))
                    with mock.patch.object(app.os, 'scandir') as listing:
                        listing.return_value.__enter__.return_value = [entry]
                        result = app.scan_processes(root)
                    self.assertTrue(result['process_complete']); self.assertTrue(result['codex_present'])
                (proc / 'cmdline').write_bytes(b'/usr/bin/ssh-agent\0-D\0')
                result = app.scan_processes(root)
                self.assertTrue(result['process_complete']); self.assertFalse(result['codex_present'])
                (proc / 'cmdline').write_bytes(b'')
                self.assertFalse(app.scan_processes(root)['process_complete'])
            (proc / 'status').write_text('malformed')
            self.assertFalse(app.scan_processes(root)['process_complete'])

    def test_zombie_leader_with_surviving_thread_holds_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); proc = root / '123'; proc.mkdir(); (root / 'self').mkdir()
            (root / 'self/mountinfo').write_text('1 0 0:1 / /proc rw - proc proc rw\n')
            (proc / 'status').write_text('Uid:\t' + '\t'.join([str(os.geteuid())] * 4) + '\n')
            fields = ['Z'] + ['1'] * 19; fields[19] = '12345'
            (proc / 'stat').write_text('123 (zombie leader) ' + ' '.join(fields))
            (proc / 'cmdline').write_bytes(b''); (proc / 'task').mkdir()
            (proc / 'task/123').mkdir(); (proc / 'task/124').mkdir()
            self.assertFalse(app.scan_processes(root)['process_complete'])
            (proc / 'task/124').rmdir()
            result = app.scan_processes(root)
            self.assertTrue(result['process_complete']); self.assertFalse(result['codex_present'])
            (root / 'self/mountinfo').write_text('1 0 0:1 / /proc rw - proc proc rw,hidepid=2\n')
            self.assertFalse(app.scan_processes(root)['process_complete'])
            (root / 'self/mountinfo').write_text('1 0 0:1 / /proc rw - proc proc rw,subset=pid\n')
            self.assertFalse(app.scan_processes(root)['process_complete'])
            (root / 'self/mountinfo').write_text('1 0 0:1 / /proc rw - proc proc rw\n')
            (proc / 'stat').unlink(); (proc / 'stat').mkdir()
            self.assertFalse(app.scan_processes(root)['process_complete'])

    def test_raw_presence_survives_unselectable_target(self):
        raw = '\t'.join(('%1', '100', '0', '@1', '/dev/pts/1', THREAD, 'fixture', 'Test'))
        with mock.patch.object(app, 'tmux', return_value=raw), mock.patch.object(
                app, 'handle_target', side_effect=app.DropError('target_busy', 'fixture')):
            result = app.handle_catalog('default')
        self.assertTrue(result['complete']); self.assertIn(THREAD, result['threads'])
        self.assertEqual([], result['chats'])

    def test_malformed_truncated_and_failed_catalog_never_prove_absence(self):
        raw = '\t'.join(('%1', '100', '0', '@1', '/dev/pts/1', THREAD, 'fixture', 'Test'))
        with mock.patch.object(app, 'tmux', return_value=raw + '\nbad-row'), mock.patch.object(
                app, 'handle_target', side_effect=app.DropError('target_busy', 'fixture')):
            self.assertFalse(app.handle_catalog('default')['complete'])
        with mock.patch.object(app, 'tmux', return_value='x' * (app.MAX_REPLY + 1)):
            result = app.handle_catalog('default')
            self.assertTrue(result['truncated']); self.assertFalse(result['complete'])
        with mock.patch.object(app, 'tmux', side_effect=app.DropError('tmux', 'fixture')):
            self.assertFalse(app.handle_inspect(THREAD, 'default')['definite'])

    def test_readonly_requests_refuse_extra_input_fields(self):
        for op in ('catalog', 'presence', 'inspect'):
            request = {'version': 1, 'op': op, 'socket': 'default', 'command': 'forbidden'}
            if op == 'inspect': request['thread'] = THREAD
            with self.assertRaises(app.DropError):
                app.handle_receive(request)

    def test_present_thread_is_held_even_when_composer_looks_empty(self):
        catalog = {'ok': True, 'tmux_ok': True, 'complete': True, 'truncated': False,
                   'threads': [THREAD], 'chats': []}
        with mock.patch.object(app, 'handle_presence', return_value=catalog, create=True):
            result = app.handle_inspect(THREAD, 'default')
        self.assertTrue(result['present'])
        self.assertFalse(result['definite'])
        self.assertIsNone(result['draft_image_marks'])

    def test_absence_requires_complete_raw_catalog(self):
        for complete in (False, True):
            catalog = {'ok': True, 'tmux_ok': True, 'complete': complete,
                       'truncated': not complete, 'threads': [], 'chats': [],
                       'process_complete': complete, 'codex_present': False}
            with mock.patch.object(app, 'handle_presence', return_value=catalog, create=True):
                result = app.handle_inspect(THREAD, 'default')
            self.assertEqual(complete, result['definite'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
