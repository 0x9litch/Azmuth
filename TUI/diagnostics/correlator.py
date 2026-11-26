"""
Correlation: turn Signals into Findings with a root cause.

No statistics or AI — explicit causal templates that join signals on a
shared ENTITY (unit, process, package, IP) inside a time window:

  1. OOM kill (process P)  ──▶ unit U failed            P≈U or result 'oom-kill'
  2. disk full             ──▶ unit failures            within 10 min
  3. unit B failed         ──▶ "Dependency failed" for A  within 30 s → cause is B
  4. restart counter / start-limit-hit for U           → cause = U's last error line
  5. package P upgraded    ──▶ unit U failed later      P≈U within 24 h
  6. kernel changed        ──▶ module / firmware errors this boot
  + standalone findings: SSH brute force, I/O errors, thermal, segfaults,
    resource pressure, reboot required, unexplained errors, limited journal.

Confidence is a label with a stated reason:
  high   – the link is explicit (systemd says 'oom-kill', names match …)
  medium – linked by time only, or the cause is the last error line seen
  low    – no supporting evidence for a cause in the analysed logs
"""

import re
from collections import defaultdict

from . import playbooks
from .models import HIGH, LOW, MEDIUM, Finding, Severity, evidence_from_event
from .rules import THRESHOLDS

OOM_WINDOW = 300
DISK_WINDOW = 600
DEPENDENCY_WINDOW = 30
UPGRADE_NAME_WINDOW = 24 * 3600
UPGRADE_ANY_WINDOW = 2 * 3600
CAUSE_LOOKBACK = 600
MAX_EVIDENCE = 12

_ERROR_WORDS = re.compile(r"error|fail|fatal|denied|refused|invalid|cannot|could not|unable|panic|emerg", re.I)


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _base(unit):
    """nginx.service -> nginx ; getty@tty1.service -> getty"""
    return unit.split("@", 1)[0].rsplit(".", 1)[0].lower()


def _names_match(a, b):
    a, b = a.lower(), b.lower()
    if len(a) < 3 or len(b) < 3:
        return a == b
    return a == b or a in b or b in a


def _ev(signal, role="observed"):
    return evidence_from_event(signal.event, role) if signal.event else None


def _cause_line(events, unit, before_ts):
    """Last error-looking line written BY the unit itself before before_ts."""
    candidates = [
        e for e in events
        if e.get("unit") == unit
        and e.get("source") not in ("systemd", "init")
        and before_ts - CAUSE_LOOKBACK <= (e.get("epoch") or 0) <= before_ts + 1
    ]
    errors = [
        e for e in candidates
        if (e.get("priority") is not None and e["priority"] <= 4) or _ERROR_WORDS.search(e.get("message", ""))
    ]
    pick = errors or candidates
    return pick[-1] if pick else None


class _Findings:
    """Collects findings and merges those with the same key."""

    def __init__(self, server):
        self.server = server
        self.by_key = {}

    def add(self, finding):
        finding.server = self.server
        finding.evidence = [e for e in finding.evidence if e][-MAX_EVIDENCE:]
        old = self.by_key.get(finding.key)
        if old is None:
            self.by_key[finding.key] = finding
            return
        old.severity = max(old.severity, finding.severity)
        old.ongoing = old.ongoing or finding.ongoing
        old.count += finding.count
        old.affected = sorted(set(old.affected) | set(finding.affected))
        seen = {(e["ts"], e["message"]) for e in old.evidence}
        old.evidence += [e for e in finding.evidence if (e["ts"], e["message"]) not in seen]
        old.evidence = old.evidence[-MAX_EVIDENCE:]
        old.first_ts = min(x for x in (old.first_ts, finding.first_ts) if x is not None) if (old.first_ts or finding.first_ts) else None
        old.last_ts = max(x for x in (old.last_ts, finding.last_ts) if x is not None) if (old.last_ts or finding.last_ts) else None
        if finding.confidence == HIGH and old.confidence != HIGH:
            old.confidence, old.confidence_reason = finding.confidence, finding.confidence_reason
            old.root_cause, old.title = finding.root_cause, finding.title

    def result(self):
        return sorted(self.by_key.values(), key=lambda f: (-int(f.severity), f.category, f.title))


# ----------------------------------------------------------------------
# main entry point
# ----------------------------------------------------------------------
def correlate(server, signals, events, ctx):
    """
    ctx: now, metrics, history, updates, failed_units, journal_access,
         ping, unmatched_errors (events with no rule), boot_ts
    """
    by = defaultdict(list)
    for s in signals:
        by[s.kind].append(s)
    for kind in by:
        by[kind].sort(key=lambda s: s.ts)

    out = _Findings(server)
    used = set()  # id() of failure signals already explained by a template

    failures = by["service_failed"] + by["main_exit"] + by["start_failed"]

    _oom(by, failures, used, out)
    _disk(by, failures, used, out, ctx)
    _dependencies(by, failures, used, out)
    _restart_loops(by, failures, used, out, events)
    _kernel(by, out, ctx)
    _service_failures(by, failures, used, out, events)
    _ssh(by, out)
    _standalone(by, out)
    _resources(by, out)
    _context(out, ctx)
    return out.result()


# ----------------------------------------------------------------------
# templates
# ----------------------------------------------------------------------
def _oom(by, failures, used, out):
    kills = []
    for s in by["oom_kill"]:  # the kernel may log one kill in two formats
        if not any(k.entities["pid"] == s.entities["pid"] and abs(k.ts - s.ts) < 10 for k in kills):
            kills.append(s)

    for kill in kills:
        proc, pid = kill.entities["process"], kill.entities["pid"]
        related, explicit = [], False
        for f in failures + by["unit_oom"]:
            if not (kill.ts - 5 <= f.ts <= kill.ts + OOM_WINDOW):
                continue
            unit = f.entities["unit"]
            if f.kind == "unit_oom" or f.entities.get("result") == "oom-kill":
                related.append(f)
                explicit = True
            elif _names_match(proc, _base(unit)) or "9/KILL" in f.entities.get("status", ""):
                related.append(f)
                explicit = explicit or _names_match(proc, _base(unit))

        units = sorted({f.entities["unit"] for f in related})
        for f in related:
            used.add(id(f))

        if units and explicit:
            confidence = HIGH
            reason = f"systemd reported the OOM kill for {', '.join(units)}" \
                if any(f.kind == "unit_oom" or f.entities.get("result") == "oom-kill" for f in related) \
                else f"process '{proc}' matches the failed unit and failed within {OOM_WINDOW // 60} min"
        elif units:
            confidence, reason = MEDIUM, "the unit failed shortly after the OOM kill (time only)"
        else:
            confidence, reason = HIGH, "the kernel log names the killed process"

        impact, checks = playbooks.oom(proc, units)
        out.add(Finding(
            severity=Severity.CRITICAL if units else Severity.ERROR,
            server="", category="memory", key=f"oom:{proc}",
            title=f"{units[0]} stopped: OOM killer terminated {proc}" if units else f"OOM killer terminated {proc}",
            root_cause=f"Memory exhaustion: the kernel's OOM killer terminated {proc} (pid {pid}).",
            confidence=confidence, confidence_reason=reason, impact=impact,
            affected=units, checks=checks,
            evidence=[_ev(kill, "cause")] + [_ev(f, "effect") for f in related],
            first_ts=kill.ts, last_ts=max([kill.ts] + [f.ts for f in related]),
        ))


def _disk(by, failures, used, out, ctx):
    logs = by["disk_full_log"]
    usage = by["disk_usage"]
    critical = [u for u in usage if u.entities["percent"] >= THRESHOLDS["disk_critical"]]

    if logs or critical:
        start = logs[0].ts if logs else ctx["now"]
        affected, effects = set(), []
        for f in failures:
            if id(f) in used:
                continue
            near = any(abs(f.ts - l.ts) <= DISK_WINDOW for l in logs) if logs else False
            if near:
                used.add(id(f))
                affected.add(f.entities["unit"])
                effects.append(f)
        writers = sorted({l.entities.get("unit") for l in logs if l.entities.get("unit")})
        percent = critical[0].entities["percent"] if critical else None
        cause = f"The root filesystem is full ({percent:.0f}% used)." if percent is not None \
            else "Writes are failing with 'No space left on device'."
        impact, checks = playbooks.disk_full("/")
        out.add(Finding(
            severity=Severity.CRITICAL, server="", category="disk", key="disk:full",
            title=f"Disk full{' — ' + ', '.join(sorted(affected)) + ' affected' if affected else ''}",
            root_cause=cause,
            confidence=HIGH if logs else MEDIUM,
            confidence_reason="'No space left on device' errors in the logs" if logs
            else "disk usage above the critical threshold (no write errors seen yet)",
            impact=impact, affected=sorted(affected | set(writers)), checks=checks,
            evidence=[_ev(l, "cause") for l in logs[-6:]] + [_ev(f, "effect") for f in effects],
            first_ts=start, last_ts=(logs[-1].ts if logs else ctx["now"]), count=max(1, len(logs)),
            ongoing=bool(critical),
        ))
    elif usage:
        pct = usage[0].entities["percent"]
        impact, checks = playbooks.disk_full("/")
        out.add(Finding(
            severity=Severity.WARNING, server="", category="disk", key="disk:usage",
            title=f"Disk / is {pct:.0f}% full",
            root_cause="The root filesystem is filling up.",
            confidence=HIGH, confidence_reason="measured with df",
            impact="Will fail writes when it reaches 100%.", checks=checks,
            first_ts=ctx["now"], last_ts=ctx["now"], ongoing=True,
        ))

    for kind, title in (("io_error", "Storage I/O errors on {d}"), ("readonly_remount", "Filesystem on {d} switched to read-only")):
        groups = defaultdict(list)
        for s in by[kind]:
            groups[s.entities["device"]].append(s)
        for dev, sigs in groups.items():
            impact, checks = playbooks.io_error(dev)
            out.add(Finding(
                severity=Severity.CRITICAL, server="", category="disk", key=f"io:{dev}",
                title=title.format(d=dev),
                root_cause="The kernel reports storage errors: failing disk or filesystem corruption.",
                confidence=HIGH, confidence_reason="kernel error messages for the device",
                impact=impact, checks=checks, affected=[dev],
                evidence=[_ev(s) for s in sigs[-6:]], first_ts=sigs[0].ts, last_ts=sigs[-1].ts, count=len(sigs),
            ))


def _dependencies(by, failures, used, out):
    for dep in by["dependency_failed"]:
        dependent = dep.entities["unit"]
        culprits = [
            f for f in failures
            if f.entities["unit"] != dependent and dep.ts - DEPENDENCY_WINDOW <= f.ts <= dep.ts + 1
        ]
        if culprits:
            culprit = culprits[-1]
            cu = culprit.entities["unit"]
            used.update(id(f) for f in culprits if f.entities["unit"] == cu)
            impact, checks = playbooks.dependency(cu, dependent)
            out.add(Finding(
                severity=Severity.ERROR, server="", category="services", key=f"dep:{cu}",
                title=f"{dependent} not started because {cu} failed",
                root_cause=f"{cu} failed, and {dependent} depends on it.",
                confidence=HIGH, confidence_reason="systemd reported the dependency failure right after it",
                impact=impact, affected=[dependent, cu], checks=checks,
                evidence=[_ev(culprit, "cause"), _ev(dep, "effect")],
                first_ts=culprit.ts, last_ts=dep.ts,
            ))
        else:
            impact, checks = playbooks.dependency("(unknown)", dependent)
            out.add(Finding(
                severity=Severity.ERROR, server="", category="services", key=f"dep:?:{dependent}",
                title=f"{dependent} not started: a dependency failed",
                root_cause="A unit it depends on failed; the failing unit is not in the analysed logs.",
                confidence=LOW, confidence_reason="the failing dependency was not found",
                impact=impact, affected=[dependent], checks=checks,
                evidence=[_ev(dep, "effect")], first_ts=dep.ts, last_ts=dep.ts,
            ))
        used.update(id(f) for f in failures if f.entities["unit"] == dependent and abs(f.ts - dep.ts) <= DEPENDENCY_WINDOW)


def _restart_loops(by, failures, used, out, events):
    units = defaultdict(list)
    for s in by["restart"]:
        if s.entities["n"] >= 3:
            units[s.entities["unit"]].append(s)
    for s in by["start_limit"]:
        units[s.entities["unit"]].append(s)

    for unit, sigs in units.items():
        sigs.sort(key=lambda s: s.ts)
        restarts = [s for s in by["restart"] if s.entities["unit"] == unit]
        first = restarts[0] if restarts else sigs[0]
        cause = _cause_line(events, unit, first.ts)
        for f in failures:
            if f.entities["unit"] == unit:
                used.add(id(f))
        count = max([s.entities.get("n", 0) for s in restarts] + [len(sigs)])
        impact, checks = playbooks.restart_loop(unit)
        evidence = ([evidence_from_event(cause, "cause")] if cause else []) + [_ev(s, "effect") for s in sigs[-4:]]
        out.add(Finding(
            severity=Severity.ERROR, server="", category="services", key=f"loop:{unit}",
            title=f"{unit} is in a restart loop",
            root_cause=f"{unit} keeps crashing: \"{cause['message'][:160]}\"" if cause
            else f"{unit} keeps crashing; it wrote no error before restarting.",
            confidence=MEDIUM if cause else LOW,
            confidence_reason="last error the unit wrote before the first restart" if cause
            else "no error output from the unit in the analysed logs",
            impact=impact, affected=[unit], checks=checks, evidence=evidence,
            first_ts=first.ts, last_ts=sigs[-1].ts, count=count,
        ))


def _kernel(by, out, ctx):
    changed = by["kernel_changed"]
    boot_ts = ctx.get("boot_ts") or 0
    problems = [s for s in by["module_error"] + by["firmware_error"] if s.ts >= boot_ts]
    if not problems:
        return
    names = sorted({s.entities.get("module") or s.entities.get("firmware") for s in problems})
    if changed:
        new, old = changed[0].entities["new"], changed[0].entities["old"]
        impact, checks = playbooks.kernel_modules(new, old, names)
        out.add(Finding(
            severity=Severity.CRITICAL, server="", category="updates", key=f"kernel:{new}",
            title=f"Drivers failing after kernel update to {new}",
            root_cause=f"The kernel changed from {old} to {new} and {', '.join(names)} failed to load in this boot.",
            confidence=HIGH, confidence_reason="module/firmware errors appear only in the first boot on the new kernel",
            impact=impact, affected=names, checks=checks,
            evidence=[_ev(s, "effect") for s in problems[-6:]],
            first_ts=problems[0].ts, last_ts=problems[-1].ts, count=len(problems),
        ))
    else:
        for name in names:
            sigs = [s for s in problems if name in (s.entities.get("module"), s.entities.get("firmware"))]
            out.add(Finding(
                severity=Severity.WARNING, server="", category="system", key=f"module:{name}",
                title=f"Kernel module/firmware {name} failed to load",
                root_cause="The module or firmware could not be loaded by the running kernel.",
                confidence=HIGH, confidence_reason="kernel error message",
                impact="The related hardware feature may not work.",
                checks=[{"title": "Module errors this boot", "command": "journalctl -b -k | grep -iE 'module|firmware'"}],
                affected=[name], evidence=[_ev(s) for s in sigs[-4:]],
                first_ts=sigs[0].ts, last_ts=sigs[-1].ts, count=len(sigs),
            ))


def _service_failures(by, failures, used, out, events):
    remaining = defaultdict(list)
    for f in failures + by["service_failed_state"]:
        if id(f) not in used:
            remaining[f.entities["unit"]].append(f)

    upgrades = by["package_upgrade"]
    failed_now = {s.entities["unit"] for s in by["service_failed_state"]}
    for unit, sigs in remaining.items():
        logged = [s for s in sigs if s.event is not None]
        ongoing = unit in failed_now
        when = logged[0].ts if logged else None

        # Template 5: did a package upgrade come right before?
        if when is not None:
            named = [u for u in upgrades if when - UPGRADE_NAME_WINDOW <= u.ts <= when and _names_match(u.entities["package"], _base(unit))]
            recent = [u for u in upgrades if when - UPGRADE_ANY_WINDOW <= u.ts <= when]
            if named or recent:
                up = (named or recent)[-1]
                pkg, old, new = up.entities["package"], up.entities["old"], up.entities["new"]
                impact, checks = playbooks.after_upgrade(unit, pkg, old, new)
                minutes = max(1, int((when - up.ts) / 60))
                others = sorted({u.entities["package"] for u in recent} - {pkg})
                out.add(Finding(
                    severity=Severity.ERROR, server="", category="updates", key=f"update:{unit}",
                    title=f"{unit} failing since {pkg} was upgraded",
                    root_cause=f"{unit} started failing {minutes} min after {pkg} was upgraded "
                               f"from {old or '?'} to {new}." + (f" Other upgrades then: {', '.join(others[:5])}." if others and not named else ""),
                    confidence=HIGH if named else MEDIUM,
                    confidence_reason=f"package '{pkg}' matches the unit and was upgraded just before the failure" if named
                    else "an upgrade happened shortly before the failure (no name match)",
                    impact=impact, affected=[unit, pkg], checks=checks,
                    evidence=[{"ts": _iso(up.ts), "source": "dpkg", "unit": "", "role": "cause",
                               "message": f"upgrade {pkg} {old} -> {new}"}] + [_ev(s, "effect") for s in logged[-3:]],
                    first_ts=up.ts, last_ts=logged[-1].ts, ongoing=ongoing,
                ))
                continue

        cause = _cause_line(events, unit, when) if when is not None else None
        status = next((s.entities.get("status") for s in logged if s.entities.get("status")), None)
        impact, checks = playbooks.service(unit)
        if cause:
            root, conf, reason = f"{unit} failed: \"{cause['message'][:160]}\"", MEDIUM, "last error the unit wrote before failing"
        elif status:
            root, conf, reason = f"{unit} exited with status {status}.", MEDIUM, "exit status reported by systemd"
        else:
            root, conf, reason = f"{unit} is in the failed state.", LOW, "the cause is not in the analysed logs"
        out.add(Finding(
            severity=Severity.ERROR, server="", category="services", key=f"svc:{unit}",
            title=f"{unit} failed", root_cause=root, confidence=conf, confidence_reason=reason,
            impact=impact, affected=[unit], checks=checks,
            evidence=([evidence_from_event(cause, "cause")] if cause else []) + [_ev(s, "effect") for s in logged[-3:]],
            first_ts=when, last_ts=logged[-1].ts if logged else None, ongoing=ongoing,
        ))


def _ssh(by, out):
    per_ip = defaultdict(list)
    for s in by["ssh_auth_fail"]:
        per_ip[s.entities["ip"]].append(s)
    for ip, sigs in per_ip.items():
        if len(sigs) < THRESHOLDS["auth_failures_warning"]:
            continue
        users = sorted({s.entities["user"] for s in sigs if s.entities.get("user")})
        impact, checks = playbooks.ssh_bruteforce(ip)
        out.add(Finding(
            severity=Severity.ERROR if len(sigs) >= THRESHOLDS["auth_failures_error"] else Severity.WARNING,
            server="", category="security", key=f"ssh:{ip}",
            title=f"{len(sigs)} failed SSH logins from {ip}",
            root_cause=f"Repeated failed logins from {ip} (users tried: {', '.join(users[:6]) or '?'}): likely password guessing.",
            confidence=HIGH if len(users) > 1 or len(sigs) >= THRESHOLDS["auth_failures_error"] else MEDIUM,
            confidence_reason=f"{len(sigs)} failures from one address" + (f" against {len(users)} user names" if len(users) > 1 else ""),
            impact=impact, affected=["ssh"], checks=checks,
            evidence=[_ev(s) for s in sigs[-6:]], first_ts=sigs[0].ts, last_ts=sigs[-1].ts, count=len(sigs),
        ))


def _standalone(by, out):
    if by["thermal"]:
        sigs = by["thermal"]
        out.add(Finding(
            severity=Severity.WARNING, server="", category="system", key="thermal",
            title="CPU thermal throttling", root_cause="The CPU overheated and the kernel slowed it down.",
            confidence=HIGH, confidence_reason="kernel throttling messages",
            impact="Lower performance; risk of shutdown if it gets worse.",
            checks=[{"title": "Temperatures (lm-sensors)", "command": "sensors"}],
            evidence=[_ev(s) for s in sigs[-4:]], first_ts=sigs[0].ts, last_ts=sigs[-1].ts, count=len(sigs),
        ))
    crashes = defaultdict(list)
    for s in by["segfault"]:
        crashes[s.entities["process"]].append(s)
    for proc, sigs in crashes.items():
        out.add(Finding(
            severity=Severity.WARNING, server="", category="system", key=f"segv:{proc}",
            title=f"{proc} crashed (segfault)", root_cause=f"{proc} accessed invalid memory and was killed by the kernel.",
            confidence=HIGH, confidence_reason="kernel segfault report",
            impact="The program stopped unexpectedly.",
            checks=[{"title": "Core dumps", "command": "coredumpctl list --no-pager | tail"}],
            affected=[proc], evidence=[_ev(s) for s in sigs[-4:]],
            first_ts=sigs[0].ts, last_ts=sigs[-1].ts, count=len(sigs),
        ))
    if by["reboot_required"]:
        pkgs = by["reboot_required"][0].entities["packages"]
        out.add(Finding(
            severity=Severity.INFO, server="", category="updates", key="reboot",
            title="Reboot required", root_cause=f"Updated packages need a reboot: {', '.join(pkgs[:6]) or 'see /var/run/reboot-required.pkgs'}.",
            confidence=HIGH, confidence_reason="/var/run/reboot-required exists",
            impact="Security fixes are installed but not active yet.",
            checks=[{"title": "Packages waiting for reboot", "command": "cat /var/run/reboot-required.pkgs"}],
        ))


def _resources(by, out):
    for kind, metric, label in (("sustained_cpu", "cpu", "CPU"), ("sustained_mem", "mem", "Memory")):
        for s in by[kind][:1]:
            impact, checks = playbooks.resource(metric)
            out.add(Finding(
                severity=Severity.ERROR if metric == "mem" and s.entities["min"] >= 95 else Severity.WARNING,
                server="", category="resources", key=f"res:{metric}",
                title=f"{label} above {s.entities['min']:.0f}% for {s.entities['minutes']} min",
                root_cause=f"{label} usage stayed between {s.entities['min']:.0f}% and {s.entities['max']:.0f}%.",
                confidence=HIGH, confidence_reason="measured continuously by Azmuth",
                impact=impact, checks=checks, first_ts=s.ts, last_ts=s.ts,
            ))
    for s in by["load_high"][:1]:
        impact, checks = playbooks.resource("load")
        out.add(Finding(
            severity=Severity.WARNING, server="", category="resources", key="res:load",
            title=f"High load ({s.entities['load1']:.2f} on {s.entities['cpus']} CPU)",
            root_cause="More tasks are runnable or waiting on I/O than the CPUs can serve.",
            confidence=HIGH, confidence_reason="load average from /proc/loadavg",
            impact=impact, checks=checks, first_ts=s.ts, last_ts=s.ts,
        ))


def _context(out, ctx):
    if ctx.get("journal_access") == "limited":
        out.add(Finding(
            severity=Severity.WARNING, server="", category="logs", key="journal-access",
            title="Only partial logs are visible",
            root_cause="The SSH user cannot read the system journal, so most problems are invisible to Azmuth.",
            confidence=HIGH, confidence_reason="the user is not root and not in systemd-journal/adm",
            impact="Diagnostics are blind to system services and the kernel.",
            checks=[{"title": "Change: allow reading the journal (then log in again)",
                     "command": "sudo usermod -aG systemd-journal \"$USER\""}],
        ))
    ping = ctx.get("ping")
    if ping is not None and not ping.get("online"):
        out.add(Finding(
            severity=Severity.WARNING, server="", category="network", key="ping",
            title="No reply to ping", root_cause="The host did not answer an ICMP echo request.",
            confidence=MEDIUM, confidence_reason="SSH may still work if a firewall drops ICMP",
            impact="Possible network or host problem.",
            checks=[{"title": "Firewall status", "command": "sudo ufw status"}],
        ))
    groups = defaultdict(list)
    for e in ctx.get("unmatched_errors", []):
        groups[e.get("unit") or e.get("source") or "?"].append(e)
    for source, items in groups.items():
        if len(items) < THRESHOLDS["unclassified_errors"]:
            continue
        impact, checks = playbooks.generic(source)
        out.add(Finding(
            severity=Severity.INFO, server="", category="logs", key=f"errors:{source}",
            title=f"{len(items)} unrecognised errors from {source}",
            root_cause="No rule recognises these errors; review them manually.",
            confidence=LOW, confidence_reason="no matching rule", impact=impact, checks=checks,
            evidence=[evidence_from_event(e) for e in items[-5:]],
            first_ts=items[0].get("epoch"), last_ts=items[-1].get("epoch"), count=len(items),
        ))


def _iso(epoch):
    from .models import iso_utc
    return iso_utc(epoch)
