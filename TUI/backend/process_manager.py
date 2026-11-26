"""
Remote process listing and safe termination.

Safety rules for kill:
- Only SIGTERM or SIGKILL.
- Never PID 1 (init/systemd) or kernel threads (children of kthreadd, PID 2).
- PID reuse protection: a PID is only signalled if it still belongs to the
  SAME process the admin saw, identified by its start time. Linux recycles
  PIDs, so "kill 4312" a few seconds later could otherwise hit a different
  program that happened to receive that number.
- Tries as the SSH user first; uses sudo only if the process belongs to
  someone else ("Operation not permitted").
"""

import shlex

from .base import BaseManager
from .errors import BackendError, CommandFailed, SudoAuthenticationFailed, SudoPasswordRequired

SIGNALS = ("TERM", "KILL")

# Exit codes of the kill script (chosen to not clash with kill's own 1).
EXIT_GONE = 66          # the process no longer exists
EXIT_DIFFERENT = 67     # the PID now belongs to a different process
EXIT_REFUSED = 68       # PID 1 / kernel thread
START_TOLERANCE_SECONDS = 2

# `date +%s` first, so start times are computed with the SERVER's clock.
_LIST_COMMAND = (
    "date +%s; "
    "LC_ALL=C ps -eo pid=,ppid=,user:32=,pcpu=,pmem=,rss=,etimes=,stat=,args= --sort=-pcpu"
)

_KILL_SCRIPT = """\
p={pid}; expected={start}; sig={sig}
[ "$p" -gt 1 ] || exit {refused}
info=$(ps -o ppid=,etimes= -p "$p") || exit {gone}
set -- $info
[ -n "$2" ] || exit {gone}
[ "$1" = 2 ] && exit {refused}
started=$(( $(date +%s) - $2 ))
diff=$(( started - expected ))
[ "${{diff#-}}" -le {tolerance} ] || exit {different}
kill -s "$sig" "$p"
"""


def _name_from_args(args):
    if args.startswith("["):  # kernel thread, e.g. [kworker/0:1]
        return args
    first = args.split(" ", 1)[0]
    return first.rsplit("/", 1)[-1] or first


def parse_ps(stdout):
    lines = stdout.splitlines()
    if not lines:
        return []

    try:
        now = int(lines[0].strip())
    except ValueError:
        raise BackendError("Process list: unexpected output")

    processes = []
    for line in lines[1:]:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
            cpu, mem = float(parts[3]), float(parts[4])
            rss_kib, elapsed = int(parts[5]), int(parts[6])
        except ValueError:
            continue
        args = parts[8]
        processes.append(
            {
                "pid": pid,
                "ppid": ppid,
                "user": parts[2],
                "cpu": cpu,
                "mem": mem,
                "rss": rss_kib * 1024,
                "elapsed": elapsed,
                "start": now - elapsed,
                "stat": parts[7],
                "name": _name_from_args(args),
                "command": args,
                "kernel_thread": pid == 2 or ppid == 2,
            }
        )
    return processes


class ProcessManager(BaseManager):
    async def list(self, name):
        res = await self.ctx.run(name, _LIST_COMMAND, timeout=20)
        if res.exit_code != 0:
            raise BackendError(f"ps failed: {res.stderr.strip() or res.exit_code}")
        return parse_ps(res.stdout)

    async def kill(self, name, pid, start, signal="TERM", command="", sudo_password=None):
        """
        Send SIGTERM/SIGKILL to *pid* if it is still the process that
        started at *start* (epoch seconds, server clock).
        """
        self.ctx.require(name)

        if signal not in SIGNALS:
            raise BackendError("Only TERM and KILL signals are allowed")

        try:
            pid, start = int(pid), int(start)
        except (TypeError, ValueError) as exc:
            raise BackendError("Invalid process id") from exc

        if pid <= 1:
            raise BackendError("Refusing to signal PID 1 (system init)")

        script = _KILL_SCRIPT.format(
            pid=pid,
            start=start,
            sig=signal,
            gone=EXIT_GONE,
            different=EXIT_DIFFERENT,
            refused=EXIT_REFUSED,
            tolerance=START_TOLERANCE_SECONDS,
        )
        details = f"pid {pid} SIG{signal}: {command[:120]}"
        shell = f"sh -c {shlex.quote(script)}"

        try:
            res = await self.ctx.run(name, shell, timeout=15)
            code, stderr = res.exit_code, (res.stderr or "")

            if code != 0 and "not permitted" in stderr.lower():
                # Someone else's process: same script, through sudo.
                try:
                    await self.ctx.run_privileged(
                        name, shell, f"kill_{signal.lower()}", f"pid {pid}", sudo_password, timeout=15
                    )
                    code = 0
                except CommandFailed as failed:
                    code, stderr = failed.exit_code, failed.stderr

            if code == EXIT_GONE:
                raise BackendError(f"Process {pid} has already exited")
            if code == EXIT_DIFFERENT:
                raise BackendError(
                    f"PID {pid} now belongs to a different process — refresh the list"
                )
            if code == EXIT_REFUSED:
                raise BackendError("Refusing to signal init or a kernel thread")
            if code != 0:
                raise BackendError(f"kill failed: {stderr.strip() or code}")

        except SudoPasswordRequired:
            raise  # not a failure yet: the UI asks for the password
        except (BackendError, SudoAuthenticationFailed):
            self.audit(f"kill_{signal.lower()}", name, "failed", details)
            raise

        self.audit(f"kill_{signal.lower()}", name, "success", details)
        return True
