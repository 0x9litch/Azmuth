"""Package upgrades (dpkg.log) and kernel changes."""

from ..models import Signal


def signals(updates):
    if not updates:
        return []
    out = [
        Signal(
            "package_upgrade",
            p["epoch"],
            {"package": p["package"], "old": p["old"], "new": p["new"], "action": p["action"]},
        )
        for p in updates.get("packages", [])
        if p.get("action") == "upgrade"
    ]
    kernel, prev = updates.get("kernel"), updates.get("prev_kernel")
    if kernel and prev and kernel != prev:
        out.append(Signal("kernel_changed", 0, {"new": kernel, "old": prev}))
    if updates.get("reboot_required"):
        out.append(Signal("reboot_required", 0, {"packages": updates.get("reboot_packages", [])}))
    return out
