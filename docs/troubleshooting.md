---
title: Troubleshooting
nav_order: 7
---

# Troubleshooting

Common problems, what causes them, and how to fix them. Most issues fall into
one of three buckets: **stale state from a previous install**, **the daemon not
actually running**, or **the portal being on a different port than you think**.

---

## Start here: `ideviewer status`

Before anything else, run:

```bash
ideviewer status
```

It prints the three facts every other question depends on — which configuration
file is in force, whether the daemon is alive, and whether the portal is
reachable and accepting the customer key:

```
=== IDEViewer Status ===
Version:  0.7.0
Platform: windows/amd64

Configuration
  [active] C:\ProgramData\IDEViewer\config.json
  [shadowed, ignored] C:\Users\you\AppData\Local\IDEViewer\config.json
  [absent] C:\Users\you\.ideviewer\config.json

  More than one configuration is present. Only the first is used;
  the others are leftovers from an earlier install. Clear them with:
    ideviewer reset --config

  Portal URL:    http://localhost:8090
  Customer key:  1a2b3c4d...ef01
  Host token:    xxxxxxxx...xxxx
  Scan interval: 30 minutes
  Enforcement:   verified
  Pinned keys:   1

Daemon
  PID file: C:\Users\you\AppData\Local\IDEViewer\ideviewer.pid
  Running (PID 14820)
  Log file: C:\Users\you\AppData\Local\IDEViewer\logs\daemon.log
  Last written: 2026-08-28 09:14:02 (48213 bytes)

Portal
  Reachable
  Customer key valid: Engineering Laptops
  Command signing: configured
```

Anything marked `[shadowed, ignored]`, `Not running`, `Unreachable`, or
`rejected` points at the matching section below.

---

## Which port is the portal on?

**One number: `8090`.** It is the default for every way of running the portal,
and `PORTAL_PORT` overrides all of them:

| How you start it | URL |
|---|---|
| `./start.sh` | `http://localhost:8090` |
| `./start.sh --docker` | `http://localhost:8090` |
| `PORTAL_PORT=9000 ./start.sh` | `http://localhost:9000` |
| `python run.py --port 9000` | `http://localhost:9000` |

Earlier releases used `5000` for the local server while Docker published `8090`
and the startup banner claimed `8080` — three numbers for one service. If you
have an older `portal/.env` pinning `PORTAL_URL=http://localhost:5000`, update
it or delete the line so the default applies.

`5000` is a poor default on macOS in any case: AirPlay Receiver binds it, so
the portal either fails to start or you reach Apple's service instead. Turn
AirPlay Receiver off in **System Settings → General → AirDrop & Handoff** if
you deliberately want port 5000 back.

Whatever port you land on, register against the same one:

```bash
ideviewer register --customer-key YOUR-KEY --portal-url http://localhost:8090
```

---

## "Customer key" returns HTTP 500

Two distinct causes, both now reported honestly rather than as a generic 500.

### The portal has no command-signing key

If the portal runs with `FLASK_CONFIG=production` and neither
`COMMAND_SIGNING_PRIVATE_KEY` nor `COMMAND_SIGNING_PRIVATE_KEY_FILE` is set,
key validation used to fail with a 500 — the very first call a new daemon
makes. Enrolment and scanning no longer depend on signing: registration
succeeds, `ideviewer status` reports `Command signing: not configured on the
portal`, and only *enforcement* commands are withheld (`/api/signing-key` and
`/api/enforcement-actions/pending` return `503 SigningUnavailable`).

To enable signing, generate a key and set it before starting the portal:

```bash
python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"
export COMMAND_SIGNING_PRIVATE_KEY='<the base64 value>'
```

Keep this stable across restarts. A new key invalidates the key every enrolled
daemon has pinned; they re-pin at their next enrolment, but until then they
will reject enforcement commands.

### The daemon is using ids from a database that no longer exists

If you rebuilt or reset the portal database but the daemon still holds its old
`config.json`, it references scan-request and enforcement-action ids that are
gone. Those are 404s. Older portals returned them as
`500 {"error": "Internal server error"}`, because the API blueprint's catch-all
error handler also swallowed ordinary HTTP errors. Now you get a real 404 (and
malformed request bodies get a real 400), which makes the fix obvious:

```bash
ideviewer reset --config
ideviewer register --customer-key YOUR-KEY --portal-url http://localhost:8090
```

---

## Updating and cleaning up

### `ideviewer update` on Windows did nothing

The installer cannot replace `ideviewer.exe` while the daemon has it open.
`ideviewer update` now stops the daemon first, installs, and restarts it. If it
reports that it could not stop the daemon:

```powershell
ideviewer stop
ideviewer status          # confirm "Not running"
ideviewer update
```

If `ideviewer stop` itself is not available (an old build), end the process in
Task Manager, or:

```powershell
taskkill /F /IM ideviewer.exe
schtasks /Delete /F /TN "IDEViewer Daemon"
```

### Reinstalling didn't give me a clean slate

IDEViewer loads its configuration from the first of these that exists, in
priority order:

| Priority | Windows | macOS | Linux |
|---|---|---|---|
| 1 (system) | `C:\ProgramData\IDEViewer\config.json` | `/Library/Application Support/IDEViewer/config.json` | `/etc/ideviewer/config.json` |
| 2 (user) | `%LOCALAPPDATA%\IDEViewer\config.json` | `~/.ideviewer/config.json` | `~/.ideviewer/config.json` |
| 3 (legacy) | `%USERPROFILE%\.ideviewer\config.json` | *(same as 2)* | *(same as 2)* |

`ideviewer register` writes the **user** path. A leftover file at the system or
legacy path therefore wins, and the daemon keeps using the previous install's
portal URL, customer key and host token — registration looks like it did
nothing. `register` now warns when this is the case, and `ideviewer status`
marks the losers `[shadowed, ignored]`.

Clear everything a reinstall would inherit:

```bash
ideviewer reset --config       # every configuration file (the usual fix)
ideviewer reset --all          # configuration, logs, git hooks, quarantine
ideviewer reset --all --yes    # no confirmation prompt
```

`reset` stops the daemon first, because removing the config from under a
running daemon leaves it using the copy already in memory. It touches only
local state — no host records are deleted from the portal. Removing a
system-level config needs elevation (`sudo`, or an administrator prompt).

To remove a host from the portal as well, use **Delete host** on its page, or
`ideviewer` deregistration before uninstalling.

---

## The daemon is not picking up scan requests

The portal shows *"Waiting for daemon to pick up request..."* and nothing
happens. Work down this list.

### 1. Is the daemon running at all?

```bash
ideviewer status
```

On Windows, older builds had two failure modes that both look like this:

- **The daemon died when you closed the terminal.** It inherited the launching
  console and received `CTRL_CLOSE_EVENT` when that window closed. It is now
  started detached, with its own process group.
- **`ideviewer stop` silently failed** — it sent `SIGTERM`, which Windows does
  not support — so it printed "already stopped", deleted the PID file, and left
  the daemon running. Duplicate daemons could then accumulate, each holding
  whichever configuration it started with, and the portal heard from the wrong
  one. `stop` now uses a Ctrl+Break to the process group and waits for the
  process to actually exit.

If it is not running:

```bash
ideviewer daemon --foreground     # run in the terminal and watch the log
```

### 2. Does it survive a reboot?

| Platform | Mechanism | Check |
|---|---|---|
| Windows | Scheduled Task at logon | `schtasks /Query /TN "IDEViewer Daemon"` |
| macOS | LaunchAgent | `launchctl print gui/$(id -u)/com.ideviewer.daemon` |
| Linux | systemd unit | `systemctl status ideviewer` |

`ideviewer register` installs the appropriate one. If the Windows task is
missing, re-run `register`, or create it by hand:

```powershell
schtasks /Create /F /TN "IDEViewer Daemon" /SC ONLOGON /RL LIMITED ^
  /TR "\"C:\Program Files\IDE Viewer\ideviewer.exe\" daemon"
```

### 3. Is it talking to the right portal?

`ideviewer status` prints the portal URL from the *active* config and probes
it. A daemon pointed at a stale URL polls a portal that has no record of your
request. See [Reinstalling didn't give me a clean slate](#reinstalling-didnt-give-me-a-clean-slate).

### 4. Is it busy with another scan?

Only one scan runs at a time. A request that arrives mid-scan stays pending and
is collected on a later poll (the daemon polls every 5 seconds). The log says:

```
Scan request #42 deferred — a scan is already running
```

### 5. Push the scan yourself

If the daemon will not collect the request, run the scan on the host and push
it. This fulfils the pending request as well as submitting the report:

```bash
ideviewer scan --push
```

```
Found pending scan request #42 — fulfilling it from this CLI run
Report pushed to portal (source: cli)
Closed pending scan request #42
```

**Does this overwrite results?** No. Scan reports are append-only rows: a push
adds one and re-derives the current-state tables, and retention only clears the
raw payload of superseded reports. What a push *can* do is mislead, by making a
hand-run scan look like routine telemetry — so every push is recorded with
`source=cli` on the report, and the scan request's log says it was fulfilled
manually rather than by the daemon. Use `--portal` instead of `--push` to
submit a report without touching any pending request.

---

## A scan request is stuck at "Pending" and Stop does nothing

Fixed in this release, and worth knowing what you were seeing.

`cancelled` was missing from the database's allowed scan-request statuses, so
the Stop button's write failed with a constraint violation and the request
never left `pending`. Because a new scan is refused while one is active
(HTTP 409), the **Trigger Scan** button then stayed disabled indefinitely.

Now:

- Stop cancels **every** active request for the host, not an arbitrary one.
  (It previously picked one row unordered while the page polled the newest, so
  they could disagree and the page kept showing "Pending".)
- A request nobody claims within **10 minutes** ages out to `timeout` on its
  own, with the reason in the log.
- A request whose daemon stops reporting progress for **30 minutes** does the
  same.
- Either way, Trigger Scan becomes usable again.

If you are on an older portal build with rows already wedged, upgrading and
running the migration is enough — the timeout sweeps them on the next page
load:

```bash
cd portal && flask db upgrade
```

---

## Webhooks are not firing

Webhook deliveries are triggered by events the portal ingests, so a daemon that
never reports produces no events. Confirm the pipeline from the bottom up:

1. `ideviewer status` shows the daemon running and the portal reachable.
2. A scan actually landed — the host page shows a recent report.
3. The subscription is enabled and subscribed to the event you expect
   (**Settings → Webhooks**).
4. Check **Recent deliveries** on the subscription for response codes; a
   non-2xx is recorded with the body.
5. Force an event with `ideviewer scan --push`, which produces a scan report
   and any resulting policy or extension-change events.

If deliveries show as queued but never sent, the portal's job queue is not
running. `./start.sh` starts an RQ worker when Redis is available; without
Redis the portal falls back to synchronous processing and logs that at startup.

---

## Reading the logs

| Platform | Daemon log |
|---|---|
| Windows | `%LOCALAPPDATA%\IDEViewer\logs\daemon.log` |
| macOS | `/tmp/ideviewer-daemon.log` (LaunchAgent) or `/var/log/ideviewer/daemon.log` |
| Linux | `/var/log/ideviewer/daemon.log`, or `journalctl -u ideviewer -f` |

`ideviewer status` prints the exact path and when it was last written — a log
that has not been touched for hours is itself the answer.

Portal logs go to the console for `./start.sh`, and to
`docker-compose logs -f portal` for `--docker`.

---

## Getting help

Include the output of `ideviewer status` (it masks the customer key and host
token) and the last 50 lines of the daemon log when opening an issue at
[github.com/securient/ideviewer-oss/issues](https://github.com/securient/ideviewer-oss/issues).
