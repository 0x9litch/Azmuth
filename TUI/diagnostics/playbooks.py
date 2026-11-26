"""
Investigation guidance per problem type: impact text and checks.

Checks are READ-ONLY commands shown to the admin (never executed
automatically). Remediation hints are clearly marked as changes.
"""

import shlex


def _q(value):
    return shlex.quote(str(value))


def _c(title, command):
    return {"title": title, "command": command}


def oom(process, units):
    checks = [
        _c("Memory right now", "free -h"),
        _c("Biggest memory users", "ps aux --sort=-%mem | head -n 15"),
        _c("Kernel OOM report", "journalctl -k --since -2h | grep -iA20 'invoked oom-killer'"),
    ]
    for unit in units[:2]:
        checks.append(_c(f"Limits of {unit}", f"systemctl show {_q(unit)} -p MemoryMax -p MemoryCurrent"))
    impact = "Service downtime: the killed process stopped." if units else "A process was killed to free memory."
    return impact, checks


def disk_full(mount="/"):
    return (
        "Writes fail: services can crash, logs and databases cannot be written.",
        [
            _c("Filesystem usage", "df -h"),
            _c("Biggest directories", f"sudo du -xh {_q(mount)} --max-depth=2 2>/dev/null | sort -h | tail -n 15"),
            _c("Journal size", "journalctl --disk-usage"),
            _c("Change (optional): shrink the journal", "sudo journalctl --vacuum-size=200M"),
        ],
    )


def io_error(device):
    return (
        "Possible failing disk or filesystem corruption: data at risk.",
        [
            _c("Kernel storage errors", "journalctl -k --since -2h | grep -iE 'i/o error|ext4-fs|xfs'"),
            _c("Disk health (needs smartmontools)", f"sudo smartctl -H /dev/{_q(device)}"),
            _c("Mounted read-only?", "findmnt -o TARGET,SOURCE,OPTIONS | grep -w ro"),
        ],
    )


def service(unit):
    return (
        f"{unit} is not running.",
        [
            _c("Unit status", f"systemctl status {_q(unit)} --no-pager"),
            _c("Unit logs", f"journalctl -u {_q(unit)} -n 50 --no-pager"),
            _c("Unit file", f"systemctl cat {_q(unit)}"),
        ],
    )


def restart_loop(unit):
    impact, checks = service(unit)
    checks.append(_c("Restart settings", f"systemctl show {_q(unit)} -p Restart -p RestartUSec -p NRestarts"))
    return f"{unit} keeps crashing and restarting.", checks


def dependency(failed_unit, dependent):
    return (
        f"{dependent} could not start because {failed_unit} failed.",
        [
            _c(f"Status of {failed_unit}", f"systemctl status {_q(failed_unit)} --no-pager"),
            _c(f"Logs of {failed_unit}", f"journalctl -u {_q(failed_unit)} -n 50 --no-pager"),
            _c(f"Dependencies of {dependent}", f"systemctl list-dependencies {_q(dependent)}"),
        ],
    )


def after_upgrade(unit, package, old, new):
    impact, checks = service(unit)
    checks = [
        _c("What changed", f"grep -h ' upgrade {package}' /var/log/dpkg.log*"),
        *checks,
    ]
    if old:
        checks.append(_c("Change (optional): roll back the package", f"sudo apt install {_q(f'{package}={old}')}"))
        checks.append(_c("Change (optional): keep it from upgrading", f"sudo apt-mark hold {_q(package)}"))
    return f"{unit} stopped working after an upgrade of {package}.", checks


def kernel_modules(new_kernel, old_kernel, modules):
    return (
        "Hardware or drivers may not work with the new kernel.",
        [
            _c("Running kernel", "uname -r"),
            _c("Module errors this boot", "journalctl -b -k | grep -iE 'module|firmware|symbol'"),
            _c("DKMS module status", "dkms status"),
            _c("Change (optional): boot the previous kernel",
               f"choose {old_kernel} under 'Advanced options' in the GRUB menu at boot"),
        ],
    )


def ssh_bruteforce(ip):
    return (
        "Someone is guessing SSH logins; a weak password could be broken.",
        [
            _c("Recent failures from this IP", f"journalctl --since -2h | grep -F {_q(ip)} | tail -n 20"),
            _c("Is password login enabled?", "sudo sshd -T | grep -i passwordauthentication"),
            _c("Change (optional): block the IP", f"sudo ufw deny from {_q(ip)}"),
        ],
    )


def resource(kind):
    commands = {
        "cpu": _c("Busiest processes", "ps aux --sort=-%cpu | head -n 15"),
        "mem": _c("Biggest memory users", "ps aux --sort=-%mem | head -n 15"),
        "load": _c("Waiting on I/O?", "vmstat 1 5"),
    }
    return "Slow responses; may lead to timeouts or OOM.", [commands[kind], _c("Overview", "top -b -n 1 | head -n 20")]


def generic(source):
    return (
        "Unknown — no rule recognises these errors.",
        [_c(f"Recent errors from {source}", f"journalctl -p err --since -2h | grep -F {_q(source)} | tail -n 30")],
    )
