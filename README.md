# Codex Drop

Drag, paste or choose screenshots from a device on your Tailscale network and
attach them to an existing Codex terminal draft on your home computer. Confirm
the destination chat first. New screenshots then upload automatically when the
page is ready. **You review and send the message in Codex yourself.**

The repository is public; a deployed screenshot page stays private to your
configured Tailscale user. Uploaded images and deployment configuration do not
belong in this repository.

## What is included

- A small browser frontend and Python backend: `share/codex-drop-web/index.html`
  and `bin/codex-drop-web`.
- A home-side receiver, `bin/codex-drop`, that verifies the live Codex process,
  stores image bytes privately and pastes attachment paths without sending Enter.
- An optional Windows PowerShell drop-window template for an existing
  WSL → SSH jump host → home route.
- A Linux user-systemd service example and offline Python/Node test fixtures.

This is a source export of the reviewed v5 application. The web path has been
used in a Windows/WSL and Tailscale Serve deployment. It is not an unattended
installer or a promise that every operating system, browser or Codex version
has been qualified. The separate terminal wrapper `codex-ssh` is not included.

## Use

1. Open your privately deployed page while connected to Tailscale.
2. Choose the intended home chat and select **Use this chat**.
3. Drop, paste or choose PNG, JPEG, GIF or WebP files. A ready page uploads new
   files automatically. Files queued before confirmation require **Attach selected**.
4. Look for **Attached to Codex draft**, then review the image and existing text
   in Codex. Send the message there when ready.

Limits are 10 images, 25 MiB each and 50 MiB per batch. HEIC is unsupported;
export it as JPEG or PNG. A failed or uncertain upload is never automatically
retried. Check the affected draft and receipt before explicitly trying again.

## Configure before installing

The home receiver needs Linux, Python 3 and tmux with a running native Codex TUI.
Chat discovery expects Byobu's `@byobu-codex-thread-id` pane metadata. The browser
route also needs a user-systemd manager and a qualified Tailscale Serve HTTPS
proxy to the backend's fixed loopback address, `127.0.0.1:8766`.

The copied scripts deliberately contain **nonworking placeholders**:

- Set `RECEIVER` in **both** Python scripts to the home machine's absolute
  receiver path. In the SSH client this is a remote home path, not the sending
  computer's home. Keep it a plain absolute path with no shell metacharacters.
- Set `THREAD` in `bin/codex-drop-web` to your chosen default chat UUID. The
  all-zero example is not a real destination. A live alternate chat can be
  selected explicitly from the server-owned catalog; nothing is confirmed by
  the placeholder.
- Keep the config outside the checkout. Its only fields are `canonical_host`
  (your lowercase Tailscale hostname and HTTPS port) and `allowed_login`
  (your exact Tailscale user login). Do not commit actual values.

See [the web deployment and safety guide](docs/codex-drop-web.md) for file
locations, ownership checks, configuration shape, proxy verification and rollback.
Create and qualify the private state and screenshot directories before starting
the example unit; a default first-run systemd compatibility symlink is refused.
Review installation steps for your host. This repository does not provision
Tailscale, ACLs, Windows forwarding, SSH accounts or Codex sessions.

The optional [Windows drop-window guide](docs/codex-drop.md) uses existing SSH
aliases and strict host-key checks. [Terminal-drop background](docs/screenshots-over-ssh.md)
describes a separate wrapper from the parent Byobu tools; that wrapper and its
tests are not shipped here.

## Retention and trust

Managed web screenshots become eligible for cleanup after **7 days**, measured
against both creation and modification times. Any running Codex process,
unresolved upload or incomplete safety check keeps copies longer. An always-on
Codex setup can retain them indefinitely. SSH-only and untracked files are
outside this cleanup. Old local-path attachments can become unavailable after
eligible files are removed.

The backend accepts one exact Tailscale login, Host and HTTPS Origin. The proxy
must replace identity headers and remote devices must be unable to reach the
backend directly. Local same-user processes are trusted; this is not a
multi-tenant service. Keep the durable journal across upgrades: uncertain or
expired operations must not become fresh uploads. Never expose the backend
publicly or bypass identity checks to fix a routing problem.

## Offline checks

Use Python 3 and Node.js already installed on your Linux development machine:

```sh
python3 -I -B tests/run_offline.py
```

In plain English: this runs both suites with synthetic images and mocked chats,
and disables the optional SSH, Windows and native-Codex integration flags. It
creates temporary test files and child processes, without using your live chat,
browser, credentials or model account. Node is required for the frontend checks.

These fixtures verify protocol, replay protection, retention guards and UI
logic. They do not prove a physical drag on your device, phone layout,
screen-reader behavior or preservation of your particular live draft.

## License

MIT. The original Cochran Research Group copyright is preserved in [LICENSE](LICENSE).
