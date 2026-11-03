#!/usr/bin/env python3
"""Automate VLESS + Reality + Vision deployment for Linux VPS."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import grp
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
from uuid import UUID, uuid4

XRAY_CONFIG_DEFAULT = "/usr/local/etc/xray/config.json"
XRAY_BINARY = "/usr/local/bin/xray"
XRAY_VERSION = "26.10.31"
INSTALL_COMMIT = "04e6f3bd9534811ed901a48c47b2c042dd64eb3a"
INSTALL_SHA256 = "934ecb26ded1089f849ac238d5170f1159fe4b6ca300d4f1e67730bd41fe58cf"
INSTALL_URL = f"https://raw.githubusercontent.com/XTLS/Xray-install/{INSTALL_COMMIT}/install-release.sh"
DEFAULT_SERVER_NAME = "www.tesla.com"


class DeploymentError(RuntimeError):
    """Raised when deployment cannot continue safely."""


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


def command_not_found_hint(cmd_name: str) -> str:
    hints = {
        "xray": "install xray first (or remove --skip-install-xray).",
        "systemctl": "systemctl is unavailable; this script requires a systemd-based Linux host.",
        "apt": "apt not found; verify distro detection or use --distro-id/--distro-like overrides.",
        "dnf": "dnf not found; verify distro detection or use --distro-id/--distro-like overrides.",
        "pacman": "pacman not found; verify distro detection or use --distro-id/--distro-like overrides.",
        "sysctl": "install procps/procps-ng package to provide sysctl.",
        "hostname": "install the hostname utility package and retry.",
    }
    return hints.get(cmd_name, "install the required command and retry.")


def run_cmd(cmd, check: bool = True, shell: bool = False, sensitive: bool = False) -> CommandResult:
    try:
        proc = subprocess.run(
            cmd,
            shell=shell,
            text=True,
            capture_output=True,
            executable="/bin/bash" if shell else None,
        )
    except FileNotFoundError as exc:
        cmd_name = cmd if shell else cmd[0]
        if check:
            if shell:
                raise DeploymentError(f"command not found while running shell command: {cmd_name}") from exc
            hint = command_not_found_hint(Path(cmd_name).name)
            raise DeploymentError(f"command not found: {cmd_name}. {hint}") from exc
        return CommandResult("", str(exc), 127)
    if check and proc.returncode != 0:
        if sensitive:
            raise DeploymentError(f"sensitive command failed (output withheld), exit={proc.returncode}")
        raise DeploymentError(
            f"command failed: {cmd}\nexit={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return CommandResult(proc.stdout.strip(), proc.stderr.strip(), proc.returncode)


def parse_os_release_text(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.lower()] = value.strip().strip('"').strip("'")
    return {"id": parsed.get("id", ""), "id_like": parsed.get("id_like", "")}


def distro_tokens(distro_id: str, distro_like: str) -> set[str]:
    tokens = set()
    for raw in (distro_id, distro_like):
        for token in raw.lower().replace(",", " ").split():
            tokens.add(token)
    return tokens


def get_upgrade_commands(distro_id: str, distro_like: str) -> list[list[str]]:
    tokens = distro_tokens(distro_id, distro_like)
    if "arch" in tokens:
        return [["pacman", "-Syu", "--noconfirm"]]
    if {"debian", "ubuntu"} & tokens:
        return [["apt", "update"], ["apt", "upgrade", "-y"]]
    if {"rhel", "fedora", "centos", "rocky", "almalinux"} & tokens:
        return [["dnf", "upgrade", "--refresh", "-y"]]
    raise DeploymentError(f"unsupported distro for package upgrade: id={distro_id}, like={distro_like}")


def firewall_ssh_port(args) -> int:
    port = args.ssh_port
    if not 1 <= port <= 65535:
        raise DeploymentError("SSH port must be between 1 and 65535")
    return port


def setup_firewall(args, distro_id: str, distro_like: str) -> None:
    if args.skip_firewall:
        return
    tokens = distro_tokens(distro_id, distro_like)
    ufw = bool({"debian", "ubuntu"} & tokens)
    firewalld = bool({"rhel", "fedora", "centos", "rocky", "almalinux"} & tokens)
    if not ufw and not firewalld:
        raise DeploymentError(
            "no supported firewall adapter for this distro; manage rules manually and use --skip-firewall"
        )

    def execute(command):
        return maybe_run(command, dry_run=args.dry_run, verbose=args.verbose)

    try:
        if args.dry_run:
            print(f"[dry-run] check firewall state; if inactive, allow SSH port {args.ssh_port} "
                  "before enabling, then verify active state")
            if ufw:
                print("[dry-run] if UFW is inactive: ufw --force enable")
            active = True
        elif ufw:
            status = run_cmd(["env", "LC_ALL=C", "ufw", "status"]).stdout
            if not re.search(r"^Status: (?:active|inactive)$", status, re.MULTILINE):
                raise DeploymentError("unable to determine UFW state")
            active = bool(re.search(r"^Status: active$", status, re.MULTILINE))
        else:
            status = run_cmd(["firewall-cmd", "--state"], check=False)
            if status.returncode == 0 and status.stdout == "running":
                active = True
            elif status.returncode == 252:
                active = False
            else:
                raise DeploymentError("unable to determine firewalld state; check its installation/service")

        ports = [args.port] if active else sorted({args.port, firewall_ssh_port(args)})
        if ufw:
            for port in ports:
                execute(["ufw", "allow", f"{port}/tcp"])
            if args.dry_run:
                return
            if not active:
                print("[info] UFW is inactive; enabling it with: ufw --force enable")
                execute(["ufw", "--force", "enable"])
            status = run_cmd(["env", "LC_ALL=C", "ufw", "status"]).stdout
            if not re.search(r"^Status: active$", status, re.MULTILINE):
                raise DeploymentError("UFW did not become active")
            for port in ports:
                if not re.search(rf"^{port}(?:/tcp)?\s+ALLOW\b", status, re.MULTILINE):
                    raise DeploymentError(f"UFW is active but no ALLOW rule found for TCP {port}")
        elif active:
            execute(["firewall-cmd", f"--add-port={args.port}/tcp"])
            execute(["firewall-cmd", "--permanent", f"--add-port={args.port}/tcp"])
        else:
            for port in ports:
                execute(["firewall-offline-cmd", f"--add-port={port}/tcp"])
            execute(["firewall-offline-cmd", "--check-config"])
            execute(["systemctl", "enable", "--now", "firewalld"])
            if run_cmd(["firewall-cmd", "--state"]).stdout != "running":
                raise DeploymentError("firewalld did not become active")
    except DeploymentError as exc:
        raise DeploymentError(
            f"firewall setup failed for TCP {args.port}; rules/state may be partially applied. "
            "Manage rules manually and use --skip-firewall if appropriate. "
            f"Details: {exc}"
        ) from exc


def get_sysctl_path(distro_id: str, distro_like: str) -> str:
    tokens = distro_tokens(distro_id, distro_like)
    if "arch" in tokens:
        return "/etc/sysctl.d/99-xray-reality.conf"
    return "/etc/sysctl.conf"


def get_sysctl_apply_command(distro_id: str, distro_like: str) -> list[str]:
    tokens = distro_tokens(distro_id, distro_like)
    if "arch" in tokens:
        return ["sysctl", "--system"]
    return ["sysctl", "-p"]


def detect_distro(args) -> tuple[str, str]:
    if args.distro_id:
        return args.distro_id.lower(), (args.distro_like or "").lower()
    if args.dry_run:
        return "ubuntu", "debian"
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        raise DeploymentError("/etc/os-release not found; pass --distro-id and --distro-like manually")
    parsed = parse_os_release_text(os_release.read_text(encoding="utf-8"))
    distro_id = parsed["id"].lower()
    distro_like = parsed["id_like"].lower()
    if not distro_id:
        raise DeploymentError("unable to parse distro id from /etc/os-release")
    return distro_id, distro_like


def parse_x25519_output(text: str) -> dict[str, str]:
    private_key = ""
    public_key = ""

    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = [p.strip() for p in line.split(":", 1)]
        key_norm = key.lower().replace(" ", "")

        if key_norm in {"privatekey", "private"}:
            private_key = value
        elif key_norm in {"publickey", "password", "password(publickey)", "public"}:
            public_key = value

    if not private_key or not public_key:
        raise DeploymentError("unable to parse x25519 output (output withheld)")

    return {"private_key": private_key, "public_key": public_key}


def validate_short_id(short_id: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{8,16}", short_id) or len(short_id) % 2:
        raise DeploymentError("short-id must be 8-16 lowercase hex chars, with even length")
    return short_id


def generate_short_id(length: int = 16) -> str:
    if length < 8 or length > 16 or length % 2:
        raise DeploymentError("short-id length must be even and between 8 and 16")
    return secrets.token_hex(8)[:length]


def build_xray_config(
    *,
    port: int,
    uuid: str,
    server_name: str,
    private_key: str,
    short_id: str,
    dest: str | None = None,
) -> dict:
    target_dest = dest or f"{server_name}:443"
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": uuid, "flow": "xtls-rprx-vision"}],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": target_dest,
                        "xver": 0,
                        "serverNames": [server_name],
                        "privateKey": private_key,
                        "shortIds": [short_id],
                    },
                },
            }
        ],
        "routing": {
            "domainStrategy": "IPOnDemand",
            "rules": [{
                "type": "field",
                "ip": [
                    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
                    "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
                    "168.63.129.16/32", "::/128", "::1/128",
                    "fc00::/7", "fe80::/10", "ff00::/8",
                ],
                "outboundTag": "blocked",
            }],
        },
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
    }


def ensure_root_or_die(dry_run: bool) -> None:
    if dry_run:
        return
    if os.geteuid() != 0:
        raise DeploymentError("please run as root (sudo)")


def ensure_sysctl_line(path: Path, key: str, value: str, dry_run: bool) -> None:
    expected = f"{key}={value}"
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    else:
        lines = []
    if any(line.strip() == expected for line in lines):
        return
    if dry_run:
        return
    with path.open("a", encoding="utf-8") as f:
        if lines and lines[-1].strip() != "":
            f.write("\n")
        f.write(expected + "\n")


def maybe_run(
    cmd,
    *,
    dry_run: bool,
    shell: bool = False,
    check: bool = True,
    verbose: bool = False,
    sensitive: bool = False,
) -> CommandResult:
    shown = cmd if shell else " ".join(cmd)
    if dry_run:
        print(f"[dry-run] {shown}")
        return CommandResult("", "", 0)
    if verbose:
        print(f"[run] {shown}")
    result = run_cmd(cmd, check=check, shell=shell, sensitive=sensitive)
    if verbose and not sensitive:
        if result.stdout:
            print(f"[stdout] {result.stdout}")
        if result.stderr:
            print(f"[stderr] {result.stderr}")
    return result


def detect_server_ip(dry_run: bool) -> str:
    if dry_run:
        return "<SERVER_IP>"
    res = run_cmd(["hostname", "-I"])
    ips = [x for x in res.stdout.split() if x]
    return ips[0] if ips else "<SERVER_IP>"


def ensure_xray_installed(args) -> None:
    if args.dry_run:
        print(f"[dry-run] require reviewed Xray {XRAY_VERSION}; install if missing/older")
        return
    installed = run_cmd([XRAY_BINARY, "version"], check=False)
    if installed.returncode == 0:
        match = re.search(r"^Xray (\d+\.\d+\.\d+)(?:\s|$)", installed.stdout)
        if not match:
            raise DeploymentError("unable to determine installed Xray version")
        if match[1] == XRAY_VERSION:
            print(f"[info] using Xray {match[1]}")
            return
        if tuple(map(int, match[1].split("."))) > tuple(map(int, XRAY_VERSION.split("."))):
            raise DeploymentError(
                "installed Xray is newer than this installer's reviewed release; update this installer first"
            )
    if args.skip_install_xray:
        raise DeploymentError(f"Xray {XRAY_VERSION} required; --skip-install-xray prevents installation")
    with urllib.request.urlopen(INSTALL_URL, timeout=30) as response:
        script = response.read()
    if hashlib.sha256(script).hexdigest() != INSTALL_SHA256:
        raise DeploymentError("official installer SHA256 mismatch; refusing to execute")
    with tempfile.TemporaryDirectory(prefix="xray-install-") as directory:
        installer = Path(directory) / "install-release.sh"
        installer.write_bytes(script)
        # Do not let inherited path overrides redirect the official installation.
        maybe_run(
            ["env", "-u", "JSON_PATH", "-u", "JSONS_PATH", "-u", "DAT_PATH",
             "bash", str(installer), "install", "--version", f"v{XRAY_VERSION}",
             "--without-geodata", "--without-logfiles", "--manually-restart-later"],
            dry_run=False, verbose=args.verbose,
        )
    version = run_cmd([XRAY_BINARY, "version"]).stdout
    if not re.search(rf"^Xray {re.escape(XRAY_VERSION)}\b", version):
        raise DeploymentError("installed Xray version does not match pinned release")


def validate_options(args) -> None:
    if not 1 <= args.ssh_port <= 65535:
        raise DeploymentError("SSH port must be between 1 and 65535")
    if not 1 <= args.port <= 65535:
        raise DeploymentError("port must be between 1 and 65535")
    if args.config_path != XRAY_CONFIG_DEFAULT:
        raise DeploymentError(f"only {XRAY_CONFIG_DEFAULT} is supported by xray.service")
    if len(args.server_name) > 253 or not all(
        re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
        for label in args.server_name.split(".")
    ):
        raise DeploymentError("server-name must be a DNS hostname, without scheme, path or wildcard")
    try:
        ipaddress.ip_address(args.server_name)
    except ValueError:
        pass
    else:
        raise DeploymentError("server-name must be a DNS hostname for certificate verification")
    parse_target(args.dest or f"{args.server_name}:443")
    if args.short_id is not None:
        validate_short_id(args.short_id)
    if args.uuid is not None:
        try:
            UUID(args.uuid)
        except ValueError as exc:
            raise DeploymentError("uuid must be a valid UUID") from exc


def parse_target(target: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(f"//{target}")
        if (not parsed.hostname or parsed.port is None or parsed.username is not None
                or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
                or any(char.isspace() for char in target) or "\\" in target):
            raise ValueError("expected host:port")
        if not 1 <= parsed.port <= 65535:
            raise ValueError("invalid port")
        return parsed.hostname, parsed.port
    except ValueError as exc:
        raise DeploymentError("target must be host:port (IPv6: [address]:port)") from exc


def check_reality_target(server_name: str, target: str, dry_run: bool) -> None:
    host, port = parse_target(target)
    if dry_run:
        print(f"[dry-run] verify {target}: TLS 1.3, h2, certificate for {server_name}, no HTTP redirect")
        return
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    try:
        with socket.create_connection((host, port), timeout=10) as connection:
            with context.wrap_socket(connection, server_hostname=server_name) as tls:
                if tls.selected_alpn_protocol() != "h2":
                    raise DeploymentError("REALITY target must support h2")
        # A separate HTTP/1.1 request checks redirects without speaking HTTP/1.1 over h2.
        context.set_alpn_protocols(["http/1.1"])
        with socket.create_connection((host, port), timeout=10) as connection:
            with context.wrap_socket(connection, server_hostname=server_name) as tls:
                request = f"HEAD / HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n"
                tls.sendall(request.encode("ascii"))
                response = http.client.HTTPResponse(tls)
                try:
                    response.begin()
                    if 300 <= response.status < 400:
                        raise DeploymentError(
                            "REALITY target redirects; choose a non-redirecting target/SNI"
                        )
                finally:
                    response.close()
    except (OSError, http.client.HTTPException) as exc:
        raise DeploymentError(f"REALITY target preflight failed: {exc}") from exc
    print(f"[info] REALITY target verified: {target} (TLS 1.3 / h2 / matching certificate / no redirect)")


def parse_reality_ping_group(output: str) -> str:
    _, separator, sni_section = output.rpartition("Pinging with SNI")
    if not separator:
        raise DeploymentError("xray tls ping output is missing the SNI section")
    if not re.search(r"^TLS Version:\s+TLS 1\.3\s*$", sni_section, re.MULTILINE):
        raise DeploymentError("REALITY target did not negotiate TLS 1.3 with SNI")
    match = re.search(
        r"^TLS Post-Quantum key exchange:\s+(?:true|false)\s+\(([^)]+)\)",
        sni_section, re.MULTILINE,
    )
    if not match:
        raise DeploymentError("xray tls ping output is missing the key-exchange result")
    return match.group(1)


def check_reality_key_exchange(server_name: str, target: str, dry_run: bool) -> None:
    """REALITY mirrors the target's TLS ServerHello and only handles X25519/X25519MLKEM768."""
    host, _ = parse_target(target)
    if dry_run:
        print(f"[dry-run] verify {target} negotiates TLS 1.3 with X25519 or X25519MLKEM768")
        return
    if not Path(XRAY_BINARY).exists():
        print("[warn] xray binary not found; skipping REALITY key-exchange preflight")
        return
    if host.lower() != server_name.lower():
        print(f"[warn] target host {host} differs from server-name {server_name}; "
              "xray tls ping uses the target host as SNI")
    try:
        proc = subprocess.run(
            [XRAY_BINARY, "tls", "ping", target],
            text=True, capture_output=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeploymentError(f"REALITY key-exchange preflight could not run: {exc}") from exc
    output = (proc.stdout + "\n" + proc.stderr).strip()
    if proc.returncode != 0:
        raise DeploymentError(
            f"REALITY key-exchange preflight failed (exit={proc.returncode}):\n{output}"
        )
    group = parse_reality_ping_group(output)
    if group.upper() not in {"X25519", "X25519MLKEM768"}:
        raise DeploymentError(
            f"REALITY target negotiated {group}; REALITY requires X25519 or X25519MLKEM768. "
            "Choose another target such as www.tesla.com."
        )
    print(f"[info] REALITY key exchange verified: {target} ({group})")


def get_service_identity() -> tuple[str, int]:
    user = run_cmd(["systemctl", "show", "xray", "--property=User", "--value"]).stdout
    group = run_cmd(["systemctl", "show", "xray", "--property=Group", "--value"]).stdout
    try:
        account = pwd.getpwnam(user)
        gid = grp.getgrnam(group).gr_gid if group else account.pw_gid
    except KeyError as exc:
        raise DeploymentError("xray.service must use an existing dedicated non-root user/group") from exc
    if account.pw_uid == 0 or gid == 0:
        raise DeploymentError("refusing to deploy to a root xray.service")
    command = run_cmd(["systemctl", "show", "xray", "--property=ExecStart", "--value"]).stdout
    expected = f"argv[]={XRAY_BINARY} run -config {XRAY_CONFIG_DEFAULT} ;"
    if expected not in command:
        raise DeploymentError("xray.service ExecStart differs from the official single-config service")
    return user, gid


def setup_bbr(args, distro_id: str, distro_like: str) -> None:
    if args.skip_bbr:
        return
    sysctl_conf = Path(get_sysctl_path(distro_id, distro_like))
    ensure_sysctl_line(sysctl_conf, "net.core.default_qdisc", "fq", args.dry_run)
    ensure_sysctl_line(sysctl_conf, "net.ipv4.tcp_congestion_control", "bbr", args.dry_run)
    maybe_run(get_sysctl_apply_command(distro_id, distro_like), dry_run=args.dry_run, verbose=args.verbose)
    if not args.dry_run:
        actual = run_cmd(["sysctl", "-n", "net.ipv4.tcp_congestion_control"]).stdout
        if actual != "bbr":
            raise DeploymentError("BBR did not take effect; check kernel support or use --skip-bbr")


def redact_config_secrets(text: str, config) -> str:
    if isinstance(config, dict):
        for key, value in config.items():
            if key in {"privateKey", "password", "id", "shortIds", "mldsa65Seed"}:
                values = value if isinstance(value, list) else [value]
                for secret in values:
                    if isinstance(secret, str) and secret:
                        text = text.replace(secret, "<REDACTED>")
            else:
                text = redact_config_secrets(text, value)
    elif isinstance(config, list):
        for value in config:
            text = redact_config_secrets(text, value)
    return text


def write_config(
    path: Path, config: dict | bytes, dry_run: bool, *, service_user: str | None = None,
    gid: int | None = None,
) -> None:
    rendered = config if isinstance(config, bytes) else (
        json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if dry_run:
        print(f"[dry-run] write config -> {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, temporary = tempfile.mkstemp(prefix=".xray-config-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            if gid is not None:
                os.fchown(stream.fileno(), os.geteuid(), gid)
            os.fchmod(stream.fileno(), 0o640)
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        if service_user is not None:
            group = ["-g", grp.getgrgid(gid).gr_name] if gid is not None else []
            result = run_cmd(
                ["runuser", "-u", service_user, *group, "--", XRAY_BINARY,
                 "run", "-test", "-config", temporary], check=False, sensitive=True,
            )
            if result.returncode:
                detail = redact_config_secrets(result.stdout + "\n" + result.stderr, config).strip()
                raise DeploymentError(
                    f"config validation failed as service user {service_user}, exit={result.returncode}\n{detail}"
                )
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def summarize_existing_config(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return ["- Existing config is not valid JSON; raw file will be backed up if you continue."]

    if not isinstance(data, dict):
        return ["- Existing config is not a JSON object."]
    inbounds = data.get("inbounds") or []
    if not inbounds:
        return ["- Existing config has no inbound entries."]
    if not isinstance(inbounds, list) or not isinstance(inbounds[0], dict):
        return ["- Existing inbound structure cannot be summarized; original file will be backed up."]
    inbound = inbounds[0]
    stream = inbound.get("streamSettings") or {}
    if not isinstance(stream, dict):
        return ["- Existing transport structure cannot be summarized; original file will be backed up."]
    reality = stream.get("realitySettings") or {}
    if not isinstance(reality, dict):
        return ["- Existing REALITY structure cannot be summarized; original file will be backed up."]
    server_names = reality.get("serverNames") or []
    return [
        f"- Protocol: {inbound.get('protocol', '<unknown>')}",
        f"- Port: {inbound.get('port', '<unknown>')}",
        f"- TLS: {stream.get('security', '<unknown>')}",
        f"- SNI: {server_names[0] if server_names else '<unknown>'}",
        f"- Target: {reality.get('target', reality.get('dest', '<unknown>'))}",
    ]


def handle_existing_config(path: Path, *, dry_run: bool, assume_yes: bool) -> Path | None:
    if path.is_symlink():
        raise DeploymentError("refusing a symlink config file")
    if not path.exists():
        return
    if path.stat().st_size == 0:
        return

    print(f"[warn] existing config detected: {path}")
    print("[info] current config summary:")
    for line in summarize_existing_config(path):
        print(line)
    print("[warn] continuing will invalidate the previous config for clients.")
    print(
        f"[info] if you continue, a backup will be created at: {path.name}.<timestamp>"
    )

    if dry_run:
        print("[dry-run] existing config check completed; no prompt and no backup created")
        return

    if not assume_yes:
        answer = input("Continue and overwrite config? [y/N]: ").strip().lower()
        if answer not in {"y", "yes"}:
            raise DeploymentError("aborted by user; existing config kept")

    timestamp = datetime.now().strftime("%y%m%d-%H%M%S-%f")
    backup_path = path.with_name(f"{path.name}.{timestamp}")
    fd = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as backup, path.open("rb") as original:
        shutil.copyfileobj(original, backup)
        backup.flush()
        os.fsync(backup.fileno())
    print(f"[info] backup created: {backup_path}")
    return backup_path


def print_client_profile(
    *,
    server_ip: str,
    port: int,
    uuid: str,
    server_name: str,
    public_key: str,
    short_id: str,
    config_path: str,
    config_written: str,
) -> None:
    print("\n=== CLIENT PROFILE ===")
    print(f"Protocol: VLESS")
    print(f"Address: {server_ip}")
    print(f"Port: {port}")
    print(f"UUID: {uuid}")
    print("Flow: xtls-rprx-vision")
    print("Transport: raw (TCP)")
    print("TLS: reality")
    print(f"SNI: {server_name}")
    print(f"PublicKey: {public_key}")
    print(f"ShortId: {short_id}")
    print("Fingerprint: chrome")
    print(f"SpiderX: /{secrets.token_hex(8)}")
    print(f"ConfigPath: {config_path}")
    print(f"ConfigWritten: {config_written}")
    print("\n[IMPORTANT] 请务必将这些信息妥善保存，客户端连接时需要用到。")


def gather_identity(args) -> tuple[str, str, str, str]:
    uuid = args.uuid or ("<UUID>" if args.dry_run else str(uuid4()))
    key_output = maybe_run(
        [XRAY_BINARY, "x25519"], dry_run=args.dry_run,
        verbose=args.verbose, sensitive=True,
    ).stdout
    if args.dry_run:
        private_key = "<PRIVATE_KEY>"
        public_key = "<PUBLIC_KEY>"
    else:
        parsed = parse_x25519_output(key_output)
        private_key = parsed["private_key"]
        public_key = parsed["public_key"]

    short_id = validate_short_id(args.short_id or generate_short_id(16))
    return uuid, private_key, public_key, short_id


def deploy(args) -> None:
    ensure_root_or_die(args.dry_run)
    validate_options(args)
    distro_id, distro_like = detect_distro(args)
    check_reality_target(args.server_name, args.dest or f"{args.server_name}:443", args.dry_run)
    config_path = Path(args.config_path)
    if config_path.parent.is_symlink():
        raise DeploymentError("refusing a symlink config directory")
    backup_path = handle_existing_config(config_path, dry_run=args.dry_run, assume_yes=args.yes)

    if not args.skip_upgrade:
        for cmd in get_upgrade_commands(distro_id, distro_like):
            maybe_run(cmd, dry_run=args.dry_run, verbose=args.verbose)

    setup_bbr(args, distro_id, distro_like)
    ensure_xray_installed(args)
    check_reality_key_exchange(args.server_name, args.dest or f"{args.server_name}:443", args.dry_run)
    service_user, gid = (None, None) if args.dry_run else get_service_identity()
    if not args.dry_run:
        config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chown(config_path.parent, 0, gid)
        os.chmod(config_path.parent, 0o750)

    uuid, private_key, public_key, short_id = gather_identity(args)

    config = build_xray_config(
        port=args.port,
        uuid=uuid,
        server_name=args.server_name,
        private_key=private_key,
        short_id=short_id,
        dest=args.dest,
    )
    setup_firewall(args, distro_id, distro_like)
    config_replaced = False
    try:
        write_config(config_path, config, args.dry_run, service_user=service_user, gid=gid)
        config_replaced = not args.dry_run
        maybe_run(["systemctl", "enable", "xray"], dry_run=args.dry_run, verbose=args.verbose)
        maybe_run(["systemctl", "restart", "xray"], dry_run=args.dry_run, verbose=args.verbose)
        if not args.dry_run:
            time.sleep(1)
        maybe_run(["systemctl", "is-active", "--quiet", "xray"], dry_run=args.dry_run)
    except (DeploymentError, OSError, KeyboardInterrupt) as exc:
        if config_replaced:
            if backup_path is not None:
                previous = backup_path.read_bytes()
                write_config(config_path, previous, False, gid=gid)
                recovered = run_cmd(["systemctl", "restart", "xray"], check=False)
                if recovered.returncode:
                    raise DeploymentError(
                        f"service failed; previous config restored but restart failed; backup: {backup_path}"
                    ) from exc
                raise DeploymentError(
                    f"service failed; previous config restored and restarted; backup: {backup_path}"
                ) from exc
            config_path.unlink(missing_ok=True)
            run_cmd(["systemctl", "stop", "xray"], check=False)
        raise

    if args.print_config:
        redacted = json.loads(json.dumps(config))
        inbound = redacted["inbounds"][0]
        inbound["settings"]["clients"][0]["id"] = "<REDACTED>"
        inbound["streamSettings"]["realitySettings"].update(
            privateKey="<REDACTED>", shortIds=["<REDACTED>"],
        )
        print(json.dumps(redacted, indent=2, ensure_ascii=False))

    server_ip = args.server_ip or detect_server_ip(args.dry_run)
    config_written = "dry-run" if args.dry_run else ("yes" if Path(args.config_path).exists() else "no")

    print_client_profile(
        server_ip=server_ip,
        port=args.port,
        uuid=uuid,
        server_name=args.server_name,
        public_key=public_key,
        short_id=short_id,
        config_path=args.config_path,
        config_written=config_written,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deploy Xray VLESS + Reality + Vision on Linux VPS"
    )
    parser.add_argument("--port", type=int, default=443, help="inbound port")
    parser.add_argument("--ssh-port", type=int, default=22,
                        help="SSH TCP port to allow before enabling an inactive firewall; default 22")
    parser.add_argument("--server-name", default=DEFAULT_SERVER_NAME, help="Reality SNI")
    parser.add_argument(
        "--target", "--dest", dest="dest", default=None,
        help="Reality target host:port, default server-name:443",
    )
    parser.add_argument("--uuid", default=None, help="existing VLESS UUID")
    parser.add_argument("--short-id", default=None, help="8-16 lowercase hex")
    parser.add_argument("--config-path", default=XRAY_CONFIG_DEFAULT, help="xray config path")
    parser.add_argument("--server-ip", default=None, help="override output server ip")
    parser.add_argument("--distro-id", default=None, help="override distro id, e.g. ubuntu/rocky/arch")
    parser.add_argument("--distro-like", default=None, help="override distro id_like, e.g. debian/rhel")

    parser.add_argument("--skip-upgrade", action="store_true", help="skip system package upgrade")
    parser.add_argument("--skip-bbr", action="store_true", help="skip BBR setup")
    parser.add_argument(
        "--skip-firewall",
        action="store_true",
        dest="skip_firewall",
        help="skip system firewall checks, port rules and activation",
    )
    parser.add_argument(
        "--skip-ufw",
        action="store_true",
        dest="skip_firewall",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--skip-install-xray", action="store_true", help="require the reviewed version without installing/upgrading"
    )

    parser.add_argument("--dry-run", action="store_true", help="print actions only")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="assume yes for overwrite prompt when existing config is found",
    )
    parser.add_argument("--verbose", action="store_true", help="print command execution details")
    parser.add_argument("--print-config", action="store_true", help="print config with credentials redacted")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        deploy(args)
    except DeploymentError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"[error] deployment failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("[error] interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
