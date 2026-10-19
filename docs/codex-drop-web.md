# Private screenshot drop page

Open the private Tailscale HTTPS page, inspect the exact home chat, and select
**Use this chat**. The default is the configured chat; the chat selector can choose
another live home Codex chat, which needs its own confirmation. Drop screenshots on a computer or use **Choose screenshots**
on a phone/tablet. The receiver attaches them to the existing Codex draft. Review
that draft and send it yourself. The page never presses Enter or submits a model
request. No per-device WSL, PowerShell, SSH session or transfer command is needed.

Supported files: PNG, JPEG, GIF and WebP; at most 10 files, 25 MiB each and
50 MiB per batch. HEIC, SVG and HTML are refused. Signature recognition is not
full image decoding; native Codex attachment verification remains authoritative.

This is source documentation. Offline fixtures do not establish an installed
service, proxy identity, native attachment or mobile-browser compatibility.
Before installing, review file hashes and modes, back up configuration, record
existing routes and plan rollback. Qualify the actual proxy and native draft
behavior on your own authorized devices before relying on the service.

## Data path and access

Browser -> Tailscale Serve HTTPS port 9443 on Windows -> WSL loopback
127.0.0.1:8766 -> fixed `python3 -I ~/.local/bin/codex-drop receive` subprocess.
The receiver gains only read-only catalog/presence/inspection requests; native process
checks and bracketed paste remain unchanged. The example default thread
`00000000-0000-4000-8000-000000000000` is not a real destination; configure
your own default chat before use. The tmux socket is fixed to `default`.
The server maps short-lived opaque choices to its own catalog and rechecks the
exact live process identity before attachment. Browser requests cannot supply
a thread UUID, pane, socket, path, target token or executable. Unavailable default
chats require an explicit choice; there is no fallback to an arbitrary chat.

Only one exact configured Tailscale operator login is accepted. Missing identities,
tagged devices without a user identity and other/shared users are denied. Ordinary
devices belonging to that operator need no second application login. Serve must
strip incoming identity headers and supply the authenticated requester identity.
The backend trusts loopback proxy requests; local programs are within the host
trust boundary. Before enabling it, qualify the actual Windows Serve-to-WSL path,
including preserved Host/Origin, real identity header replacement, and refusal of
direct backend access from LAN/tailnet devices. A loopback bind alone is not proof
of that boundary across every WSL networking mode. Do not broaden the bind or
allow identity-free access to solve a forwarding failure.

Host must match the configured hostname and port. Mutations require the exact
HTTPS Origin, JSON content type and a short-lived unpredictable nonce held only
in page memory. No cookies (other ports share hostname cookies), CORS, browser
storage secrets, URL capabilities, third-party assets, remote image fetches or
stored screenshot-serving endpoints. The response uses no-store and hashed inline
script/style CSP. Nonces and request URLs are not logged.

## Receipts and interrupted uploads

The browser reads and hashes files locally before requesting a server-issued
operation ticket. Tickets expire after at most five minutes, belong to one
15-minute page session and one confirmed physical chat, and disappear on restart.
Only the newest unused ticket in that session is valid. Protocol-v1 pages must
reload. Unknown, expired, replaced, foreign-session or compacted IDs return 410;
they never become new uploads. Matching retained operations return their saved
receipt; changed content or physical target conflicts.

Before invoking the fixed receiver, the server durably reserves an uncertain
receipt and a fingerprint binding screenshots to the exact target. Jobs are
serialized and session, ticket, target and capacity are rechecked at admission.
A crash, timeout or lost response leaves an uncertain receipt; that operation is
never dispatched again, including after restart. Ticket numbers persist across compaction. Permanent legacy-ID tombstones also
exclude arbitrary pre-v5 UUIDs from future ticket issuance, so even repeated randomness cannot recycle a previously admitted ID that was preserved
for migration. An ID already removed by an earlier modified/compacting build
cannot be recovered by migration; a future random-prefix collision would be
negligible but not impossible. An upgrade must qualify its own previous journal history. A deployment that
previously compacted arbitrary IDs cannot recover records that no longer exist.

Inspect each receipt **and its affected Codex draft** after any uncertain, blocked,
partial or unverified result. A missing receipt cannot establish what attached.
Remove already attached images from the local queue before explicitly attaching
again. Recovery lists each recorded chat/thread; a legacy receipt can lack that
identity. Check every affected draft before marking the listed uploads as checked.
The checkbox and **Mark as checked** action save a separate durable
acknowledgement; they never rewrite the original attachment result or upload
anything. Queued files require an explicit Attach after recovery. A later drop,
focus, reconnect, session renewal or page-resume event cannot resend them.
Closing/backgrounding a mobile page does not cancel an in-flight attachment.
Saving bytes and attaching images are separate outcomes.

Session time remaining is visible. Focus, visibility, pageshow and connectivity
events refresh readiness without an upload. Renewal preserves confirmation only
when every public target field still matches the chat the user confirmed. A
changed or closed chat requires another explicit confirmation.

State lives under `~/.local/state/codex-drop-web` (0700), with private 0600 files,
one instance lock and an 8 MiB SQLite page quota. All unresolved operations are
retained and displayed; admission stops at 64 unresolved uploads. Existing
legacy journals above this limit migrate without losing any unresolved record.
The most recent 32 settled/acknowledged receipt details are kept; older details
are compacted transactionally. A compacted ID cannot be admitted again. The
journal stores metadata/results, never screenshot bytes, base64 or session
nonces. Preserve it across upgrades and restarts.

## Seven-day managed screenshot retention

Only validated web-receiver receipts register files in the managed-file ledger.
Legacy web receipts with complete provenance can be registered during migration.
SSH-only screenshots, untracked files, browser evidence, arbitrary neighbors and
paths outside the exact store are never adopted or deleted. The fixed store is
`~/.local/share/codex-drop/screenshots`. Managed provenance survives receipt
compaction and restart.

Cleanup runs on startup and hourly, serialized with upload/selection jobs. Seven
days is the **earliest cleanup eligibility**, measured against both recorded UTC
creation and the file's modification time. Files from unresolved uploads are held
until the user durably acknowledges checking the draft. Any running current-user Codex process or Codex wrapper holds all eligible
files, even outside the selected tmux socket. A bounded, read-only process scan
(8192 entries, two seconds, bounded metadata) must complete with none present,
and raw tmux thread enumeration must be complete and show the target absent.
Ownership comes from bounded real/effective Uid fields in process status, not
/proc directory ownership: non-dumpable processes may look root/overflow-owned.
When the executable link is hidden, a readable command line still identifies
Codex; an unknown live command line holds cleanup. Hidden/restricted procfs
views are incomplete. Unknown ownership, unreadable metadata, malformed/truncated scans or time/count
limits also hold files. No argv, environment or draft text is returned or stored.
A zombie group leader is considered gone only after a bounded task-directory
check rules out surviving threads. Other-user/root Codex processes whose real
and effective UIDs both differ from this operator are outside this cleanup
model; the app only attaches to this operator's native TUI. The classifier
excludes this service, receiver, scanner, byobu helpers and shells
that merely mention Codex. Persistent Codex daemons also cause the conservative
hold; on an always-running setup screenshots may stay indefinitely. An empty
visible editor is never used to authorize deletion. Storage status shows managed/held counts, last run and cleanup
errors; partial deletion is reported truthfully. Held files and permanent tombstone metadata can eventually
fill the database quota, at which point new work fails closed rather than
deleting evidence or unresolved records to make room.

For an eligible file, cleanup walks private parents with descriptor-relative
no-follow opens, never creates/chmods directories, and requires current ownership,
0700 directories, a 0600 regular file with one link, the recorded bounded size
and SHA-256, stable metadata and rechecked path entries. It rechecks complete global process absence and raw thread absence immediately
before unlinking only that basename. Changed files,
links, unsafe paths and inspection/I/O failures remain held. Empty batch directories are permanent filesystem tombstones: the receiver
creates each random batch directory exclusively before writing files, so a name
collision refuses before creation. Deleted managed records remain metadata
tombstones, and legacy provenance migration runs only once. Neither a future
upload nor receipt compaction recycles them. Shutdown stops the worker and preserves the journal.

After all Codex processes close, eligible files can be removed. Later resuming,
backtracking or recalling an older local-path attachment may then fail because
the file has expired. The stored conversation is not a promise to keep these
local copies. A process starting between the final check and unlink can encounter
the same missing-file outcome; permanent batch tombstones prevent substitution
with a newer image. Manual deletion of tombstones by a malicious same-UID process
is outside the accepted host threat model. No native history scanning is added.

Version-matched upstream source supports these distinctions: [local image
conversion](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/protocol/src/models.rs#L2018-L2043)
reads image bytes, and the [rollout test](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/core/tests/suite/image_rollout.rs#L150-L241)
checks inline image content. This does not prove all event/history representations
are path-free. [TUI input projection](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/tui/src/chatwidget/user_messages.rs#L780-L850)
can restore local paths, and [backtrack](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/tui/src/app_backtrack.rs#L470-L495)
rebuilds local attachments. [Composer history](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/tui/src/bottom_pane/chat_composer_history.rs#L39-L79)
distinguishes full in-session attachments from persistent text-only history.
The upstream [hardening helper](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/process-hardening/src/lib.rs#L38-L64)
can make Linux processes non-dumpable; the presence guard therefore handles that
state independently of whether this particular CLI build enables it.
These are source observations, not an installed-native E2E or a guarantee about
future Codex versions; cleanup therefore uses the stronger global presence veto.

## Ownership checks at startup

Before every unit start, exactly one `ExecStartPre=+` command checks ownership
outside the filesystem/user namespace used by the main process. It first requires
the kernel identity UID map and a real view of the home ancestor, then opens every
component of the state path with directory descriptors and no-follow. It refuses
foreign owners, unsafe writable ancestors, symlinks and a final directory that is
not owned by the user with exactly 0700 permissions. The check writes no files,
creates no directories or journal, and starts no server. Any refusal blocks startup.
The existing root-owned sticky-ancestor rule remains part of this strict check.

The config JSON still contains only the hostname and allowed login. Both startup
modes share the existing fixed state path under the user's home; neither accepts
a state-path argument or a browser-selected directory. The state directory must
already exist, created by a reviewed initialization step, before this unit starts.
This also avoids systemd's first-run state/config compatibility symlink.

Inside the sandbox, systemd can hide root's UID as the overflow UID. Only a
non-final, non-writable ancestor with that unmapped UID receives the narrow
exception: the kernel UID map must be non-identity with root unmapped, the overflow
UID itself must be unmapped, and `INVOCATION_ID` must be nonempty. Overflow-owned
ancestors receive no sticky/writable exception. Mapped owners retain the original
rules; the final directory still requires the process UID and exactly 0700.

The accepted threat model protects against other users and unsafe ownership or
permissions. Malicious processes already running as the same UID, including the
app itself, are excluded: they could already replace the installed script. The
systemd marker is context for this model, not an unforgeable attestation. There is
no writable attestation file or cached inode-based ownership approval. The gate
checks current real ownership before each start. The unit restarts on failure
after five seconds, with at most three starts in five minutes; the pre-start gate
runs every time. The single-instance lock and other sandbox restrictions remain.
Enabling the user unit starts it with the user service manager while WSL is
running. Qualify user lingering and WSL systemd on the deployment host;
this does not itself launch WSL after a Windows reboot.

These are source checks. Before installing changed scripts and units, review
the exact files and rollback plan. Passing fixtures does not prove the live
pre-start gate or native receiver works inside the real unit.

The unit bounds memory at 1280 MiB. An offline probe with two full-size HTTP
bodies, framing copies and the receiver's pure image-validation function peaked
at about 866 MiB RSS. That probe deliberately retained extra fixture buffers;
it is a conservative model, not a measurement of a running systemd cgroup.
The limit leaves about 414 MiB above that observation for separate-process,
allocator and filesystem overhead. Read actual cgroup memory and failure state
during live verification; do not claim the offline model proves live memory.

## Offline source verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_codex_drop_web.py
```
In plain English: this tests the adapter with in-memory requests, fake receiver
calls and anonymous pipes. Socket creation and server binding are forbidden by
the harness. Node also checks the actual frontend controller and DOM event handlers offline. This
does not start the service or send anything to the real chat.

## Installation preparation

Freeze source and destination hashes/modes, configuration shape, unit, route
baseline and rollback plan before changing a deployment. Preserve any existing
routes and use a separate private 9443 route. Never enable Funnel, reset all
Serve configuration, alter unrelated profiles/services, restart live Codex,
unlink tmux sessions or overwrite unrelated clients to deploy this application.

Review the following file destinations and permissions:

| Source | Destination | Mode |
| --- | --- | --- |
| `bin/codex-drop-web` | `~/.local/bin/codex-drop-web` | 0700 |
| `share/codex-drop-web/index.html` | `~/.local/share/codex-drop-web/index.html` | 0600 |
| `services/codex-drop-web.service` | `~/.config/systemd/user/codex-drop-web.service` | 0600 |
| `bin/codex-drop` | `~/.local/bin/codex-drop` | 0700 |

The existing private config remains unchanged at mode 0600; do not copy its
contents into source control or shared reports. Record its hash and the
two-field shape without exposing the values.

Application data/config directories must be owned by the user and mode 0700.
The existing program parent ~/.local/bin is owned and mode 0755; it may remain
0755 provided no group/other write is allowed. Never chmod shared parent folders. The existing
receiver screenshot directory must already be safely created/qualified before
the unit's writable path is used. The unit keeps access to the existing
`/tmp/tmux-UID/default` socket; `PrivateTmp=yes` would hide it. The changed unit is source
only until installed. Review its bounded restart behavior and enablement
before starting it on a real host.

Example config shape (replace placeholders privately):

```json
{"canonical_host":"YOUR-HOME-NODE.YOUR-TAILNET.ts.net:9443","allowed_login":"YOUR-EXACT-TAILSCALE-USER-LOGIN"}
```
In plain English: this permits one Tailscale user's devices at one private home
address. The actual hostname must be lowercase. A wrong or missing login denies
access; do not add passwords or provider credentials to this file.

After completing the deployment review, install the files and start the single
adapter unit. Preserve an existing correct 9443 route without rewriting it.
If a new route is needed, use the existing Windows Tailscale command after
qualifying the loopback path and recording all existing routes:

```sh
tailscale serve --bg --https=9443 http://127.0.0.1:8766
```
In plain English: this adds a private Tailscale HTTPS route on port 9443 to the
reviewed local adapter. It changes networking configuration and should run only after you have reviewed the installation. Verify every existing route remains.

Rollback must stop/disable the v5 service and preserve the live database and
screenshots. It may restore the exact previous program bytes you recorded, but **must not
restart v4 against a journal v5 has compacted**: v4 accepts arbitrary client IDs
and cannot preserve v5's old-operation refusal. Restoring old availability needs
a separate compatible recovery design, never a database reset or downgrade.
Remove only the screenshot route you own when your rollback plan calls for it:

```sh
tailscale serve --https=9443 off
systemctl --user disable --now codex-drop-web.service
```
In plain English: this removes only the owned screenshot route and stops its user
service. It preserves the existing routes, screenshots and receipts. Compare the
remaining Serve configuration with the baseline; do not reset the whole service.

## Verify your deployment

Read installed artifacts back and match the frozen digests. Verify service bind,
Windows-to-WSL reachability, real Serve identity, strict Host/Origin and remote
backend refusal. Test actual browser desktop drop and mobile picker with an
authorized device. Prove private screenshot bytes/digest and a visible native
attachment in the exact intended draft, with earlier text intact and zero
automatic Enter/provider requests. Exercise failure/receipt recovery without
replaying uncertain operations. Test selected-chat identity, session renewal,
durable acknowledgement, bounded recovery/autostart, and maintenance holds.
Read-only cleanup fixtures remain distinct from production deletion; do not
backdate or delete live screenshots to manufacture a retention result. Remove
only disposable fixtures you created for the test. Record route, browser,
device, native draft and image-readability results separately. A passing offline
suite or saved file alone does not establish a complete working upload flow.
