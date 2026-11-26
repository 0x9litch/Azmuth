"""
Remote system monitoring: host info, CPU, memory, disk, load.
"""

import re
from datetime import datetime

from .base import BaseManager
from .errors import BackendError

# dpkg.log uses the server's LOCAL time, so the script also prints the
# server's UTC offset (date +%z) to convert those timestamps correctly.
_UPDATES_SCRIPT = (
    "printf 'tz=%s\\n' \"$(date +%z)\"; "
    "printf 'kernel=%s\\n' \"$(uname -r)\"; "
    "printf 'prev_kernel=%s\\n' \"$(journalctl -b -1 -k --no-pager -o cat -q 2>/dev/null "
    "| grep -m1 '^Linux version' | awk '{print $3}')\"; "
    "[ -f /var/run/reboot-required ] && echo reboot=1; "
    "sed 's/^/reboot_pkg=/' /var/run/reboot-required.pkgs 2>/dev/null; "
    "for f in /var/log/dpkg.log.1 /var/log/dpkg.log; do [ -r \"$f\" ] && "
    "grep -hE ' (upgrade|install) ' \"$f\"; done | tail -n 400 | sed 's/^/dpkg=/'; true"
)

_DPKG_LINE = re.compile(
    r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (upgrade|install) (\S+) (\S+) (\S+)$"
)


def parse_updates(stdout):
    info = {
        "kernel": None,
        "prev_kernel": None,
        "reboot_required": False,
        "reboot_packages": [],
        "packages": [],
    }
    tz = "+0000"
    raw = []
    for line in stdout.splitlines():
        key, _, value = line.partition("=")
        value = value.strip()
        if key == "tz" and value:
            tz = value
        elif key == "kernel":
            info["kernel"] = value or None
        elif key == "prev_kernel":
            info["prev_kernel"] = value or None
        elif key == "reboot":
            info["reboot_required"] = True
        elif key == "reboot_pkg" and value:
            info["reboot_packages"].append(value)
        elif key == "dpkg":
            raw.append(value)

    for line in raw:
        m = _DPKG_LINE.match(line)
        if not m:
            continue
        stamp, action, pkg, old, new = m.groups()
        try:
            epoch = datetime.strptime(f"{stamp} {tz}", "%Y-%m-%d %H:%M:%S %z").timestamp()
        except ValueError:
            continue
        info["packages"].append(
            {
                "epoch": epoch,
                "action": action,
                "package": pkg.split(":", 1)[0],
                "old": None if old == "<none>" else old,
                "new": new,
            }
        )
    return info


class MonitoringManager(BaseManager):
    async def system_info(self, name):
        self.ctx.require(name)

        script = (
            "printf 'uptime='; cat /proc/uptime | awk '{print int($1)}'; "
            "printf 'hostname='; hostname; "
            "printf 'kernel='; uname -r; "
            "printf 'load='; cut -d' ' -f1-3 /proc/loadavg; "
            "printf 'cpus='; nproc 2>/dev/null || echo 1; "
            "printf 'os='; . /etc/os-release 2>/dev/null; "
            'echo "$PRETTY_NAME"'
        )

        res = await self.ctx.run(name, script)

        if res.exit_code != 0:
            raise BackendError(
                f"system info failed: {res.stderr.strip() or res.exit_code}"
            )

        info = {
            "uptime": "-",
            "hostname": "-",
            "kernel": "-",
            "os": "-",
            "load": "-",
            "cpus": "-",
        }

        for line in res.stdout.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                if key in info:
                    info[key] = value.strip()

        return info

    async def cpu_percent(self, name):
        self.ctx.require(name)

        script = (
            "read -r _ u1 n1 s1 i1 w1 irq1 sirq1 st1 _ < /proc/stat; "
            "sleep 0.2; "
            "read -r _ u2 n2 s2 i2 w2 irq2 sirq2 st2 _ < /proc/stat; "
            "t1=$((u1+n1+s1+i1+w1+irq1+sirq1+st1)); "
            "t2=$((u2+n2+s2+i2+w2+irq2+sirq2+st2)); "
            "dt=$((t2-t1)); "
            "di=$((i2-i1)); "
            'if [ "$dt" -le 0 ]; then echo 0; else '
            "echo $(((dt-di)*100/dt)); fi"
        )

        res = await self.ctx.run(name, script, timeout=10)
        raw = res.stdout.strip()

        if not raw:
            raise BackendError("CPU: no output from /proc/stat sampling")

        try:
            return float(raw)
        except ValueError as exc:
            raise BackendError(f"CPU: cannot parse '{raw}'") from exc

    async def memory(self, name):
        self.ctx.require(name)

        res = await self.ctx.run(name, "free -b | awk '/Mem:/ {print $2, $3, $4}'")
        parts = res.stdout.strip().split()

        if len(parts) < 3:
            raise BackendError("Memory: unexpected free output")

        try:
            total, used, free = int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError as exc:
            raise BackendError("Memory: cannot parse free output") from exc

        percent = (used / total * 100) if total else 0.0

        return {"total": total, "used": used, "free": free, "percent": percent}

    async def disk(self, name):
        self.ctx.require(name)

        res = await self.ctx.run(name, "df -B1 / | awk 'NR==2 {print $2, $3, $4, $5}'")
        parts = res.stdout.strip().split()

        if len(parts) < 4:
            raise BackendError("Disk: unexpected df output")

        try:
            total = int(parts[0])
            used = int(parts[1])
            free = int(parts[2])
            percent = float(parts[3].rstrip("%"))
        except ValueError as exc:
            raise BackendError("Disk: cannot parse df output") from exc

        return {"total": total, "used": used, "free": free, "percent": percent}

    async def snapshot(self, name):
        """
        Collect every metric, tolerating individual failures.

        Returns {"info", "cpu", "mem", "disk", "errors"} where a failed
        metric is None and its message is appended to "errors".
        """
        snap = {"info": None, "cpu": None, "mem": None, "disk": None, "errors": []}

        for key, getter in (
            ("info", self.system_info),
            ("cpu", self.cpu_percent),
            ("mem", self.memory),
            ("disk", self.disk),
        ):
            try:
                snap[key] = await getter(name)
            except BackendError as exc:
                snap["errors"].append(f"{key}: {exc}")

        return snap

    async def updates_info(self, name):
        """Recent package upgrades, running vs previous kernel, reboot flag."""
        self.ctx.require(name)
        res = await self.ctx.run(name, _UPDATES_SCRIPT, timeout=30)
        return parse_updates(res.stdout or "")
