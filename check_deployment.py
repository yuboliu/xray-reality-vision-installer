#!/usr/bin/env python3
"""Read-only health check for a VLESS + REALITY + Vision deployment."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from reality_installer import (
    XRAY_BINARY,
    XRAY_CONFIG_DEFAULT,
    XRAY_VERSION,
    DeploymentError,
    parse_reality_ping_group,
    redact_config_secrets,
    run_cmd,
)

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
_results: list[str] = []


def report(status: str, title: str, detail: str = "") -> None:
    print(f"[{status}] {title}" + (f": {detail}" if detail else ""))
    _results.append(status)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def parse_xray_version(text: str) -> str | None:
    match = re.search(r"^Xray (\d+\.\d+\.\d+)(?:\s|$)", text, re.MULTILINE)
    return match.group(1) if match else None


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def fetch_latest_xray(timeout: float = 10) -> str:
    request = urllib.request.Request(
        "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
        headers={"User-Agent": "xray-reality-vision-installer-check"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.load(response)
    tag = data.get("tag_name", "")
    match = re.search(r"v?(\d+\.\d+\.\d+)", tag)
    if not match:
        raise DeploymentError(f"unexpected latest release tag: {tag!r}")
    return match.group(1)


def parse_ufw_status(text: str) -> dict:
    status = ""
    default = ""
    rules = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Status:"):
            status = line.split(":", 1)[1].strip().lower()
        elif line.startswith("Default:"):
            default = line.split(":", 1)[1].strip().lower()
        else:
            match = re.match(
                r"^(\S+(?:\s+\(v6\))?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)?\s*(.*)$",
                line,
            )
            if match:
                rules.append({
                    "to": match.group(1).strip(),
                    "action": match.group(2).upper(),
                    "direction": (match.group(3) or "").upper(),
                    "from": match.group(4).strip(),
                })
    return {"status": status, "default": default, "rules": rules}


def find_ufw_rule(parsed: dict, port: int, ipv6: bool = False) -> dict | None:
    wanted = {str(port), f"{port}/tcp"}
    for rule in parsed["rules"]:
        has_v6 = "(v6)" in rule["to"]
        if has_v6 != ipv6:
            continue
        if rule["to"].replace(" (v6)", "") not in wanted:
            continue
        if rule["action"] == "ALLOW" and rule["direction"] in ("", "IN"):
            return rule
    return None


def sysctl(name: str) -> str:
    result = run_cmd(["sysctl", "-n", name], check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def load_config(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def ping_target(target: str) -> str:
    try:
        proc = subprocess.run(
            [XRAY_BINARY, "tls", "ping", target],
            text=True, capture_output=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeploymentError(f"tls ping could not run: {exc}") from exc
    output = (proc.stdout + "\n" + proc.stderr).strip()
    if proc.returncode != 0:
        raise DeploymentError(f"tls ping failed (exit={proc.returncode})")
    return parse_reality_ping_group(output)


def check_system_info() -> None:
    try:
        release = platform.freedesktop_os_release()
        os_name = release.get("PRETTY_NAME") or release.get("NAME") or "unknown"
    except OSError:
        os_name = "unknown"
    report(INFO, "OS", os_name)
    report(INFO, "kernel", platform.release())
    ufw = run_cmd(["ufw", "--version"], check=False)
    if ufw.returncode == 0 and ufw.stdout:
        report(INFO, "UFW version", ufw.stdout.splitlines()[0])


def check_xray_versions(offline: bool) -> None:
    result = run_cmd([XRAY_BINARY, "version"], check=False)
    installed = parse_xray_version(result.stdout) if result.returncode == 0 else None
    if installed:
        report(PASS, "Xray installed", installed)
    else:
        report(FAIL, "Xray installed", "not found or version unreadable")
    report(INFO, "Installer baseline", XRAY_VERSION)

    if offline:
        report(INFO, "Latest stable", "skipped (--offline)")
        return
    try:
        latest = fetch_latest_xray()
    except (OSError, ValueError, DeploymentError) as exc:
        report(WARN, "Latest stable", f"could not check: {exc}")
        return
    report(INFO, "Latest stable", latest)
    if installed:
        if version_tuple(installed) < version_tuple(latest):
            report(WARN, "Xray update", f"installed {installed} < latest {latest}; review before upgrading")
        elif version_tuple(installed) == version_tuple(latest):
            report(PASS, "Xray version", "installed matches latest stable")
        else:
            report(WARN, "Xray version", f"installed {installed} > latest {latest}; verify release channel")
    if version_tuple(XRAY_VERSION) < version_tuple(latest):
        report(WARN, "Installer baseline", f"{XRAY_VERSION} < latest {latest}; update the installer after review")
    elif version_tuple(XRAY_VERSION) == version_tuple(latest):
        report(PASS, "Installer baseline", "matches latest stable")


def check_ufw(port: int, ssh_port: int) -> None:
    if not shutil.which("ufw"):
        report(WARN, "UFW", "ufw not installed; firewall check skipped")
        return
    result = run_cmd(["env", "LC_ALL=C", "ufw", "status", "verbose"], check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "ufw status failed").strip().splitlines()
        report(WARN, "UFW", detail[0] if detail else "ufw status failed; run as root")
        return
    parsed = parse_ufw_status(result.stdout)
    if parsed["status"] != "active":
        report(
            FAIL, "UFW",
            f"inactive; run: ufw allow {ssh_port}/tcp; "
            f"ufw allow {port}/tcp; ufw --force enable",
        )
        return
    report(PASS, "UFW", "active")
    if "deny (incoming)" not in parsed["default"]:
        report(WARN, "UFW default", parsed["default"] or "not reported")
    rule = find_ufw_rule(parsed, port)
    if rule:
        report(PASS, f"UFW TCP {port}", f"ALLOW from {rule['from']}")
    else:
        report(FAIL, f"UFW TCP {port}", f"missing; run: ufw allow {port}/tcp")
    if find_ufw_rule(parsed, port, ipv6=True):
        report(PASS, f"UFW TCP {port} (IPv6)", "present")
    else:
        report(WARN, f"UFW TCP {port} (IPv6)", "missing; add only if the VPS uses IPv6")
    if find_ufw_rule(parsed, ssh_port):
        report(PASS, f"UFW SSH {ssh_port}", "present")
    else:
        report(WARN, f"UFW SSH {ssh_port}", f"missing; run: ufw allow {ssh_port}/tcp")


def check_sysctl() -> None:
    qdisc = sysctl("net.core.default_qdisc")
    if qdisc == "fq":
        report(PASS, "qdisc", "fq")
    elif qdisc:
        report(WARN, "qdisc", f"{qdisc}; expected fq")
    else:
        report(WARN, "qdisc", "could not read net.core.default_qdisc")
    congestion = sysctl("net.ipv4.tcp_congestion_control")
    if congestion == "bbr":
        report(PASS, "congestion control", "bbr")
    elif congestion:
        report(FAIL, "congestion control", f"{congestion}; expected bbr")
    else:
        report(FAIL, "congestion control", "could not read net.ipv4.tcp_congestion_control")
    available = sysctl("net.ipv4.tcp_available_congestion_control")
    if "bbr" in available.split():
        report(PASS, "BBR support", "available")
    else:
        report(FAIL, "BBR support", "bbr not listed in tcp_available_congestion_control")
    for path in (Path("/etc/sysctl.conf"), Path("/etc/sysctl.d/99-xray-reality.conf")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
        except OSError:
            continue
        if "net.core.default_qdisc=fq" in text and "net.ipv4.tcp_congestion_control=bbr" in text:
            report(PASS, "sysctl persistence", str(path))
            return
    report(WARN, "sysctl persistence", "fq/BBR lines not found in the checked sysctl files")


def check_service_and_config(config_path: str, offline: bool) -> None:
    active = run_cmd(["systemctl", "is-active", "xray"], check=False)
    if active.returncode == 0 and active.stdout == "active":
        report(PASS, "xray.service", "active")
    else:
        report(FAIL, "xray.service", active.stdout or active.stderr or "not active")
    enabled = run_cmd(["systemctl", "is-enabled", "xray"], check=False)
    if enabled.returncode == 0 and enabled.stdout == "enabled":
        report(PASS, "xray.service enabled", "yes")
    else:
        report(WARN, "xray.service enabled", enabled.stdout or "not enabled at boot")

    try:
        config = load_config(config_path)
    except (OSError, ValueError) as exc:
        report(FAIL, "config", f"cannot read {config_path}: {exc}")
        return
    inbounds = config.get("inbounds") or []
    if not inbounds:
        report(FAIL, "config", "no inbounds")
        return
    inbound = inbounds[0]
    stream = inbound.get("streamSettings") or {}
    reality = stream.get("realitySettings") or {}
    port = inbound.get("port")
    if inbound.get("protocol") == "vless" and stream.get("security") == "reality":
        report(PASS, "inbound", f"VLESS + REALITY on port {port}")
    else:
        report(FAIL, "inbound", f"unexpected protocol/security: {inbound.get('protocol')} / {stream.get('security')}")
    if stream.get("network") in ("raw", "tcp"):
        report(PASS, "transport", str(stream.get("network")))
    else:
        report(WARN, "transport", f"unexpected network: {stream.get('network')}")
    clients = (inbound.get("settings") or {}).get("clients") or []
    if clients and clients[0].get("flow") == "xtls-rprx-vision":
        report(PASS, "flow", "xtls-rprx-vision")
    else:
        report(FAIL, "flow", "first client missing xtls-rprx-vision")
    target = reality.get("target") or reality.get("dest")
    server_names = reality.get("serverNames") or []
    if target and server_names:
        report(PASS, "REALITY target", f"{target}; SNI {', '.join(server_names)}")
    else:
        report(FAIL, "REALITY target", "target/serverNames missing")

    if port:
        ss = run_cmd(["ss", "-lntp"], check=False)
        if ss.returncode == 0 and re.search(rf":{re.escape(str(port))}\b[^\n]*xray", ss.stdout):
            report(PASS, "listener", f"xray listening on {port}")
        elif ss.returncode == 0:
            report(FAIL, "listener", f"no xray listener on {port}")
        else:
            report(WARN, "listener", "ss unavailable")

    user = run_cmd(["systemctl", "show", "xray", "--property=User", "--value"], check=False).stdout.strip()
    if not user or user == "root":
        report(FAIL, "service user", user or "empty; refusing root")
    else:
        result = run_cmd(
            ["runuser", "-u", user, "--", XRAY_BINARY, "run", "-test", "-config", config_path],
            check=False,
        )
        if result.returncode == 0:
            report(PASS, "config validation", f"xray run -test as {user}")
        else:
            detail = redact_config_secrets(result.stdout + "\n" + result.stderr, config).strip()
            lines = detail.splitlines()
            report(FAIL, "config validation", lines[-1][:300] if lines else f"exit={result.returncode}")

    if not offline and target:
        try:
            group = ping_target(target)
        except DeploymentError as exc:
            report(WARN, "REALITY key exchange", str(exc))
        else:
            if group.upper() in {"X25519", "X25519MLKEM768"}:
                report(PASS, "REALITY key exchange", f"{target} ({group})")
            else:
                report(FAIL, "REALITY key exchange", f"{target} negotiated {group}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only health check for VLESS + REALITY + Vision")
    parser.add_argument("--config-path", default=XRAY_CONFIG_DEFAULT)
    parser.add_argument("--port", type=int, default=None, help="Xray TCP port; default from config")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH TCP port; default 22")
    parser.add_argument("--offline", action="store_true", help="skip GitHub and target network checks")
    args = parser.parse_args(argv)
    for name, value in (("port", args.port), ("ssh-port", args.ssh_port)):
        if value is not None and not 1 <= value <= 65535:
            parser.error(f"--{name} must be between 1 and 65535")

    port = args.port
    try:
        config = load_config(args.config_path)
        if port is None:
            raw_port = (config.get("inbounds") or [{}])[0].get("port")
            if isinstance(raw_port, int):
                port = raw_port
            elif isinstance(raw_port, str) and raw_port.isdigit():
                port = int(raw_port)
    except (OSError, ValueError):
        config = None

    ssh_port = args.ssh_port

    check_system_info()
    check_xray_versions(args.offline)
    if not is_root():
        report(WARN, "system checks", "rerun with sudo for UFW/sysctl/service checks")
    else:
        if port:
            check_ufw(port, ssh_port)
        else:
            report(WARN, "UFW", "cannot determine Xray port; pass --port")
        check_sysctl()
        check_service_and_config(args.config_path, args.offline)

    passed = sum(1 for status in _results if status == PASS)
    warnings = sum(1 for status in _results if status == WARN)
    failures = sum(1 for status in _results if status == FAIL)
    print(f"\nSummary: {passed} passed, {warnings} warnings, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
