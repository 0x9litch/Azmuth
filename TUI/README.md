# Azmuth — Linux System Administration TUI

Keyboard-driven terminal UI for managing Linux servers over SSH
(Textual 8.x + AsyncSSH 2.24).

## Run

```bash
pip install -r TUI/requirements.txt
python -m TUI            # run from the folder that CONTAINS TUI/
```

All imports inside the package are relative, so the folder can be renamed
(e.g. to `azmuth/`) and run with `python -m azmuth`.

## Layout

```
TUI/
├── main.py / __main__.py     entry point (python -m TUI)
├── core/                     transport + persistence (no UI, no business rules)
│   ├── database.py           SQLite: servers, fingerprints, audit, settings,
│   │                         metric history, incidents + evidence
│   └── connection.py         AsyncSSH: pinned host keys, commands, sudo -S, SFTP
├── backend/                  application logic — one manager per feature
│   ├── backend.py            Backend facade: backend.servers / .monitoring / ...
│   ├── base.py               BackendContext: audit, run(), run_privileged() (sudo)
│   ├── errors.py             BackendError, SudoPasswordRequired, SudoAuthenticationFailed
│   ├── key_manager.py        managed SSH key: generate, passphrase, unlock in RAM, lock
│   ├── settings.py           non-secret preferences (key path, theme, mouse)
│   ├── server_manager.py     registry, connect/disconnect, fingerprint, key install, ping
│   ├── collector.py          background collection for every connected server
│   │                         (single data source for the tabs, diagnostics and the API)
│   ├── monitoring.py         CPU, memory, disk, host info, load, package updates
│   ├── process_manager.py    process list + safe kill (start-time check, sudo)
│   ├── service_manager.py    systemd list / failed / start / stop / restart
│   ├── terminal_manager.py   remote command execution
│   ├── file_manager.py       SFTP ops with sudo fallback, server-to-server transfer
│   └── log_manager.py        journalctl (JSON, incremental by cursor) + audit trail
├── diagnostics/              rule-based problem analysis → incidents
│   ├── models.py             Severity (4 levels), Signal, Finding, Report
│   ├── rules/                one module per problem type + THRESHOLDS
│   ├── correlator.py         joins signals into root causes with confidence
│   ├── playbooks.py          impact + read-only checks per problem
│   ├── engine.py             DiagnosticsEngine.analyze() / quick_alerts()
│   ├── incidents.py          IncidentStore: lifecycle, dedupe, recurrence, export
│   ├── redaction.py          secret removal before data leaves Azmuth
│   └── service.py            DiagnosticsService: collector → engine → store
├── api/                      read-only HTTP API for the web dashboard (off by default)
│   ├── server.py             aiohttp on 127.0.0.1 inside the TUI's event loop
│   ├── security.py           token, Host check, GET only, rate limit, headers
│   ├── token.py              ~/.config/azmuth/api-token (0600)
│   └── routes.py             endpoints
├── docs/API.md               contract for the web team (+ examples/)
└── ui/
    ├── app.py                shell: shared state, global keys, theme, mouse, spawn/ask/busy
    ├── ssh_flows.py          unlock key, connect one/all, install key, key manager
    ├── commands.py           Ctrl+P command palette
    ├── formatting.py         bytes / uptime / permissions / gauges
    ├── tabs/                 base.py + dashboard, services, terminal, files, logs, activity
    ├── dialogs/              confirm (+prompt), password (sudo), server (form, fingerprint),
    │                         keys (key manager, generate, passphrase, secret prompt),
    │                         transfer, help
    ├── widgets/              ServerList, StatusBar, KeyHints, MetricCard, SearchBar, HistoryInput
    └── styles/               theme.py (colours + Textual theme), azmuth.tcss
```

Dependency direction: `ui → backend → core`, `backend → diagnostics`, `backend → api`.
The UI never runs SQL or touches AsyncSSH directly.

## Tabs

| # | Tab | What it shows |
|---|---|---|
| 1 | Dashboard | all servers (ping, SSH, incidents), live metrics, 10-min trend, alerts |
| 2 | Services | systemd units, failed filter, start / stop / restart |
| 3 | Processes | live process list, sort, search, TERM / KILL with safety checks |
| 4 | Terminal | run commands on the selected server |
| 5 | Files | SFTP browser, upload / download / transfer, sudo fallback |
| 6 | Logs | live journal: level ≥, time range, unit, source, search |
| 7 | Incidents | diagnosed problems: root cause, confidence, evidence, checks |
| 8 | Activity | audit log of every action |

Data is collected in the background for every connected server
(metrics/processes 5 s, logs 15 s, services 30 s, diagnostics 60 s,
updates 5 min); tabs only redraw.

## Keyboard

| Global | |
|---|---|
| `F1`–`F8` or `1`–`8` | switch tab (numbers don't work while typing in a field) |
| `[` / `]` | previous / next server |
| `Ctrl+P` | command palette: switch / connect / disconnect servers, jump to tabs |
| `a` / `e` / `Ctrl+D` | add / edit / delete server |
| `c` / `x` | connect / disconnect the selected server |
| `C` / `X` | connect / disconnect ALL servers (passphrase asked once) |
| `I` | install your public key on the selected server (asks its password) |
| `K` | SSH key manager: generate, add/change passphrase, use existing, lock |
| `Ctrl+T` | theme picker — restyles the whole UI, remembered |
| `F9` | mouse on/off (off = select & copy text with the terminal), remembered |
| `A` | read-only API on/off for the web dashboard (see docs/API.md) |
| `?` | full keyboard reference |
| `q` | quit (asks first if SSH sessions are open) |

Each tab shows its own keys in the bottom bar; `?` lists all of them.

## SSH keys

First launch: if `~/.ssh/azmuth_ed25519` exists it is adopted; otherwise
Azmuth offers to create it (ed25519, comment `azmuth`, optional passphrase,
encrypted in OpenSSH format with bcrypt KDF — same as `ssh-keygen`).

Adding a server with a password does what `ssh-copy-id` does:

1. fetch the host key and ask you to verify the fingerprint,
2. log in once with the password (only to the verified host),
3. append the public key to `~/.ssh/authorized_keys` (no duplicates,
   correct 700/600 permissions; the key is sent on stdin),
4. connect with the key to prove it works.

Never stored: passwords, passphrases, decrypted keys. An unlocked key lives
in memory until you lock it (`K` → `l`) or quit. Only the key *path*, theme
and mouse preference are saved (settings table).

Once every server accepts the key you can set `PasswordAuthentication no`
in the servers' `/etc/ssh/sshd_config`.

## Tests

`TUI/tests/` starts a fake SSH server (AsyncSSH, with fake `sudo`,
`systemctl`, `journalctl`) on `127.0.0.1:2299` and drives the real UI
headless. Nothing touches your VMs.

```bash
python TUI/tests/diag_unit.py    # diagnostics rules, correlation, incidents, redaction
python TUI/tests/e2e.py          # every tab end to end
python TUI/tests/e2e_api.py      # API security + data (also refreshes docs/examples)
python TUI/tests/e2e_keys.py     # SSH key flows
python TUI/tests/e2e_stress.py   # channel limits, fast switching, dropped servers
python TUI/tests/e2e_fixes.py    # sudo / file-transfer edge cases
```
