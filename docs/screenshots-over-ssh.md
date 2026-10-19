# Related terminal wrapper (not included in this repository)

This background guide describes `codex-ssh` from the separate Byobu tools.
Neither that wrapper nor its test suite is shipped in Codex Drop. For the
included browser and Windows-window routes, start with the repository README.

`codex-ssh` runs on the computer sending the screenshot. It connects through
OpenSSH, transfers a dropped image over that same connection, and pastes its
verified remote path into Codex. Codex shows an image attachment in the draft.
Press Enter yourself when the message is ready.

The client needs Python 3 and POSIX OpenSSH: Linux, macOS, or WSL inside Windows
Terminal. The remote machine needs Python 3, Codex and a POSIX-compatible login
shell (such as Bash or zsh). Plain PowerShell
`ssh.exe`, phone SSH clients and mosh do not gain file-drop support from a
server installation. The actual sending client still needs to be confirmed.

## Connect

Use the separately installed wrapper with your existing SSH host alias.

Use `codex-ssh my-host` for a normal remote shell instead. Options `-p`, `-l`,
`-i`, `-J` and `-F` select the SSH port, user, identity file, jump host and
configuration file. Put these options before the host. Existing authentication
and host-key checks stay in effect; the wrapper stores no credentials.

## Attach an image

With the Codex composer focused, drag one or more saved PNG, JPEG, WebP or GIF
files from the sending computer into the terminal. Quoted filenames with spaces,
Windows drive paths and WSL `/mnt/c/` paths are supported. The foreground app
must enable bracketed paste, as Codex normally does. Without that terminal mode,
input passes through as text and cannot be recognized as a file drop.

On WSL, you can also press **Windows+Shift+S**, capture an area, return to the
remote Codex composer and press **Ctrl+Alt+V**. The wrapper reads the image from
the sending computer's clipboard. It does not replace clipboard contents.
Windows Terminal often uses Ctrl+V for its own text paste, so use Ctrl+Alt+V for
the screenshot. If no local image is available, the key passes through unchanged.

Wait for the attachment to appear, describe what should be fixed, then submit.
For example: “Read this screenshot, research the error, and fix it in this
project. Verify the fix.” Ordinary typing and non-image pastes pass through.

Uploads are limited to 25 MiB per image and 50 MiB per drop. The wrapper checks
image signatures; Codex performs its own image decoding. Remote files remain
under `~/.local/share/codex/screenshots/` in private directories, because Codex
may read them only when the message is submitted. Failed partial uploads are
removed. Successful uploads have no automatic cleanup; delete an old upload only after the
relevant conversation no longer needs it.

If transfer fails, the wrapper reports the error and adds nothing to the draft.
The terminal pauses during image uploads; output and keystrokes resume when
the upload completes or times out.
It does not retry or open a second authentication connection. Confirm the host
has Python 3, that the SSH master is still connected, and that the remote
screenshot directory belongs to you with permissions 0700.

## Local screenshot paste

For Codex running on the same Windows/WSL computer, its built-in image paste is
already available: Windows+Shift+S, then Ctrl+Alt+V in Codex. That local clipboard
route alone does not transfer screenshots from a different SSH client.

## Developer checks

The separate wrapper project owns its parsing, transfer and integration tests.
Those checks cannot be run from this repository.

Controlled tests do not prove the physical drag gesture in your actual SSH
client. Verify one real screenshot attachment in the intended draft before
relying on the separately installed wrapper.
