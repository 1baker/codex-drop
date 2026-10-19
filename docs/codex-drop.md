# Drop screenshots into an existing Codex chat

Codex Drop is a small Windows window for saved PNG, JPEG, GIF and WebP files.
Keep your current WSL terminal and its Bastion-to-home SSH session open. Drop a
saved screenshot onto the window; it sends the actual image bytes through a
background WSL process and the existing SSH aliases, then attaches the private
home copy to the confirmed Codex draft. Review the draft and press Enter yourself.

This is a companion drop window. Windows Terminal cannot transfer a work-local
file to a remote computer merely by inserting its local pathname into SSH.

## One-time setup

Review the home-side Python helper and Windows template before installing.
Install `bin/codex-drop` at
`/home/YOUR_HOME_USER/.local/bin/codex-drop` and the template at
`/home/YOUR_HOME_USER/.local/share/codex-drop/CodexDrop.ps1`. Existing unrelated files are
not part of this installation. The helper needs Python 3 and tmux at home;
the work computer needs Windows PowerShell 5.1, WSL Python 3 and its existing
`ssh bastion` alias. Bastion needs its existing `ssh home` alias.

Generate a bundle for the exact existing Codex thread and tmux socket. For example,
replace `THREAD_UUID` with that chat's actual UUID and choose a new output filename:

```bash
python3 -I /home/YOUR_HOME_USER/.local/bin/codex-drop bundle \
  --thread THREAD_UUID --socket default \
  --output /home/YOUR_HOME_USER/.local/share/codex-drop/CodexDrop-work.ps1
```

In plain English: this prepares a Windows drop window for one particular chat,
and prints its hash and one-time setup command. The output file is written at
home; choose a fresh output path because the bundle command replaces that path.

Paste the generated bootstrap into ordinary **Windows PowerShell on the work
computer**. It uses hidden WSL SSH to fetch the bundle, verifies its SHA-256,
creates `%LOCALAPPDATA%\CodexDrop\CodexDrop.ps1`, and opens the window. It refuses
to replace a different existing Windows script or a linked destination. No new
WSL tab or terminal reconnect is needed. PowerShell's execution-policy override
applies only to that process.

For later launches, put this in the Windows Run box or a shortcut:

```text
powershell -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%LOCALAPPDATA%\CodexDrop\CodexDrop.ps1"
```

In plain English: this opens the already-installed drop window without opening a
new WSL tab or changing your current terminal connection. It runs the local script
with a process-only execution-policy override.

## Use

1. Click **Test route** if you need to check background authentication.
2. Click **Refresh target**, check the chat identity, then **Use this chat**.
3. Drag saved screenshot files from Explorer onto the drop area. With **Send on
   drop** checked, they upload immediately to that confirmed chat. Otherwise,
   click **Send queued**.
4. A successful result says both **transferred** and **attachment verified**.
   Check the images in the existing Codex composer and submit the prompt yourself.

Existing draft text is preserved. Each image uses a private tmux paste buffer,
and the helper never sends Enter or writes the clipboard. If Codex restarts,
refresh and confirm its new process before sending another image. Other chats,
shells, copy mode, and recognizable approval menus are refused.

The window accepts saved file drops. Browser and Outlook virtual images must be
saved first. Up to 10 images, 25 MiB each and 50 MiB total are allowed per batch.
No filename is executed as a command. The client checks image signatures,
lengths and SHA-256 before SSH; home checks them again and reads saved files back.

## Failures

- **Bastion/home authentication or host key:** background SSH uses BatchMode and
  strict host-key checking. An interactive password or one-time code used by the
  existing terminal might not be available to it. The window reports the failed
  hop without changing credentials, keys, known_hosts or profiles.
- **Transferred only:** bytes arrived at home, but attachment was blocked or not
  verified. Read the status, inspect the composer, and avoid blindly uploading
  again. A pasted pathname can remain if Codex did not recognize the image.
- **Timeout or missing reply:** the remote result can be uncertain. Check the
  composer before explicitly retrying queued files. Automatic sending is disabled
  after every failed or timed-out upload and after an unverified attachment.
- **Target changed:** refresh the target and confirm the intended chat again.

Screenshots are retained under
`~/.local/share/codex-drop/screenshots/<random-drop>/<random-file>`. Directories
are private (0700), files are private (0600), and failed partial writes are
removed. Completed transfers are retained even when attachment fails, so you can
inspect the result. No network listener, browser service, public link or tunnel
is created. Attaching an image does not submit it to a model provider.

## Verification

The default suite checks framing, image limits, hashes, safe storage and target
refusals with synthetic data. Optional tests use real disposable loopback SSH
servers, actual Windows PowerShell 5.1 without showing a form, and an isolated
native Codex TUI pointed at a loopback model stub that forbids all model POSTs:

```bash
python3 tests/test_codex_drop.py
CODEX_DROP_SSH=1 CODEX_DROP_PS=1 CODEX_DROP_NATIVE=/absolute/path/to/raw/codex \
  python3 tests/test_codex_drop.py
```

In plain English: the first command runs local checks. The second also exercises
temporary SSH servers, a hidden Windows form and a disposable Codex chat. These
tests create and clean up their own files and processes; they do not use your
live chat, clipboard, SSH keys or provider account.

Passing these checks does not prove the work computer's background authentication
or physical drag gesture. Those require one actual work-client drop into the
intended existing chat. Keep that result separate from controlled test evidence.
