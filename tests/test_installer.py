import io
import hashlib
import os
import stat
import subprocess
from types import SimpleNamespace
import reality_installer as installer
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from reality_installer import (
    CommandResult,
    build_parser,
    command_not_found_hint,
    DeploymentError,
    build_xray_config,
    get_sysctl_apply_command,
    get_sysctl_path,
    get_upgrade_commands,
    handle_existing_config,
    parse_os_release_text,
    parse_x25519_output,
    print_client_profile,
    run_cmd,
)


class ParseX25519OutputTests(unittest.TestCase):
    def test_parse_legacy_public_key_output(self):
        output = "PrivateKey: pri_key\nPublicKey: pub_key\n"
        parsed = parse_x25519_output(output)
        self.assertEqual(parsed["private_key"], "pri_key")
        self.assertEqual(parsed["public_key"], "pub_key")

    def test_parse_password_alias_output(self):
        output = "Private key: pri_key\nPassword: pub_key\n"
        parsed = parse_x25519_output(output)
        self.assertEqual(parsed["private_key"], "pri_key")
        self.assertEqual(parsed["public_key"], "pub_key")

    def test_parse_current_stable_password_public_key_label(self):
        output = "PrivateKey: private\nPassword (PublicKey): public\nHash32: hash\n"
        self.assertEqual(parse_x25519_output(output), {
            "private_key": "private", "public_key": "public",
        })


class BuildXrayConfigTests(unittest.TestCase):
    def test_build_reality_config_contains_vision_and_reality(self):
        cfg = build_xray_config(
            port=443,
            uuid="u-1",
            server_name="www.microsoft.com",
            private_key="pri",
            short_id="6baad05011122233",
        )

        inbound = cfg["inbounds"][0]
        client = inbound["settings"]["clients"][0]
        reality = inbound["streamSettings"]["realitySettings"]

        self.assertEqual(inbound["protocol"], "vless")
        self.assertEqual(client["flow"], "xtls-rprx-vision")
        self.assertEqual(inbound["streamSettings"]["security"], "reality")
        self.assertEqual(reality["serverNames"], ["www.microsoft.com"])
        self.assertEqual(reality["target"], "www.microsoft.com:443")


class DistroAdapterTests(unittest.TestCase):
    def test_parse_os_release_prefers_id_like(self):
        parsed = parse_os_release_text(
            'ID=rocky\nID_LIKE="rhel fedora"\nNAME="Rocky Linux"\n'
        )
        self.assertEqual(parsed["id"], "rocky")
        self.assertEqual(parsed["id_like"], "rhel fedora")

    def test_upgrade_commands_for_debian(self):
        cmds = get_upgrade_commands("ubuntu", "debian")
        self.assertEqual(cmds, [["apt", "update"], ["apt", "upgrade", "-y"]])

    def test_upgrade_commands_for_rhel(self):
        cmds = get_upgrade_commands("rocky", "rhel fedora")
        self.assertEqual(cmds, [["dnf", "upgrade", "--refresh", "-y"]])

    def test_upgrade_commands_for_arch(self):
        cmds = get_upgrade_commands("arch", "")
        self.assertEqual(cmds, [["pacman", "-Syu", "--noconfirm"]])

    def test_sysctl_path_arch_uses_sysctl_d(self):
        path = get_sysctl_path("arch", "")
        self.assertEqual(path, "/etc/sysctl.d/99-xray-reality.conf")

    def test_sysctl_apply_arch(self):
        cmd = get_sysctl_apply_command("arch", "")
        self.assertEqual(cmd, ["sysctl", "--system"])


class FirewallTests(unittest.TestCase):
    def test_active_ufw_adds_only_custom_listener_tcp_port(self):
        args = build_parser().parse_args(['--port', '8443'])
        responses = [
            CommandResult('Status: active', '', 0),
            CommandResult('', '', 0),
            CommandResult('Status: active\n8443/tcp ALLOW Anywhere', '', 0),
        ]
        with patch.object(installer, 'run_cmd', side_effect=responses) as command:
            installer.setup_firewall(args, 'ubuntu', 'debian')
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            ['env', 'LC_ALL=C', 'ufw', 'status'],
            ['ufw', 'allow', '8443/tcp'],
            ['env', 'LC_ALL=C', 'ufw', 'status'],
        ])

    def test_active_firewalld_adds_rules_without_reload_or_restart(self):
        args = build_parser().parse_args(['--port', '8443'])
        with patch.object(installer, 'run_cmd', return_value=CommandResult('running', '', 0)) as command:
            installer.setup_firewall(args, 'rocky', 'rhel fedora')
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            ['firewall-cmd', '--state'],
            ['firewall-cmd', '--add-port=8443/tcp'],
            ['firewall-cmd', '--permanent', '--add-port=8443/tcp'],
        ])

    def test_inactive_ufw_preserves_ssh_before_enabling_and_verifies_state(self):
        args = build_parser().parse_args(['--port', '8443', '--ssh-port', '2222'])
        responses = [CommandResult('Status: inactive', '', 0), CommandResult('', '', 0),
                     CommandResult('', '', 0), CommandResult('', '', 0),
                     CommandResult('Status: active\n2222/tcp ALLOW Anywhere\n8443/tcp ALLOW Anywhere', '', 0)]
        with patch.object(installer, 'run_cmd', side_effect=responses) as command:
            installer.setup_firewall(args, 'ubuntu', 'debian')
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            ['env', 'LC_ALL=C', 'ufw', 'status'],
            ['ufw', 'allow', '2222/tcp'], ['ufw', 'allow', '8443/tcp'],
            ['ufw', '--force', 'enable'], ['env', 'LC_ALL=C', 'ufw', 'status'],
        ])

    def test_active_ufw_without_port_rule_fails(self):
        args = build_parser().parse_args(['--port', '8443'])
        responses = [
            CommandResult('Status: active', '', 0),
            CommandResult('', '', 0),
            CommandResult('Status: active\n443/tcp ALLOW Anywhere', '', 0),
        ]
        with patch.object(installer, 'run_cmd', side_effect=responses):
            with self.assertRaisesRegex(DeploymentError, 'no ALLOW rule'):
                installer.setup_firewall(args, 'ubuntu', 'debian')

    def test_dry_run_ufw_shows_force_enable(self):
        args = build_parser().parse_args(['--dry-run', '--port', '8443'])
        output = io.StringIO()
        with patch.object(installer, 'run_cmd') as command, redirect_stdout(output):
            installer.setup_firewall(args, 'ubuntu', 'debian')
            command.assert_not_called()
        self.assertIn('[dry-run] if UFW is inactive: ufw --force enable', output.getvalue())

    def test_inactive_firewalld_stages_rules_before_starting_service(self):
        args = build_parser().parse_args(['--port', '8443', '--ssh-port', '2222'])
        responses = [CommandResult('', 'not running', 252)] + [CommandResult('', '', 0)] * 4
        responses.append(CommandResult('running', '', 0))
        with patch.object(installer, 'run_cmd', side_effect=responses) as command:
            installer.setup_firewall(args, 'rocky', 'rhel')
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            ['firewall-cmd', '--state'],
            ['firewall-offline-cmd', '--add-port=2222/tcp'],
            ['firewall-offline-cmd', '--add-port=8443/tcp'],
            ['firewall-offline-cmd', '--check-config'],
            ['systemctl', 'enable', '--now', 'firewalld'],
            ['firewall-cmd', '--state'],
        ])

    def test_ssh_port_defaults_to_22_and_is_validated(self):
        self.assertEqual(build_parser().parse_args([]).ssh_port, 22)
        for value in ['0', '65536']:
            with self.assertRaises(DeploymentError):
                installer.validate_options(build_parser().parse_args(['--ssh-port', value]))
        for value in (0, 65536):
            args = build_parser().parse_args([])
            args.ssh_port = value
            with self.assertRaises(DeploymentError):
                installer.firewall_ssh_port(args)

    def test_unknown_state_never_enables_firewall(self):
        for distro, output, code in [('ubuntu', 'unexpected', 0), ('rocky', 'failed', 1)]:
            with self.subTest(distro=distro), \
                    patch.object(installer, 'run_cmd', return_value=CommandResult(output, '', code)) as command:
                with self.assertRaisesRegex(DeploymentError, 'determine'):
                    installer.setup_firewall(build_parser().parse_args([]), distro, '')
                self.assertEqual(command.call_count, 1)

    def test_activation_that_does_not_take_effect_fails(self):
        args = build_parser().parse_args(['--ssh-port', '22'])
        responses = [CommandResult('Status: inactive', '', 0)] * 5
        with patch.object(installer, 'run_cmd', side_effect=responses):
            with self.assertRaisesRegex(DeploymentError, 'did not become active'):
                installer.setup_firewall(args, 'ubuntu', 'debian')

    def test_skip_flags_perform_no_checks_or_firewall_operations(self):
        for flag in ['--skip-firewall', '--skip-ufw']:
            with self.subTest(flag=flag), patch.object(installer, 'run_cmd') as command:
                installer.setup_firewall(build_parser().parse_args([flag]), 'ubuntu', 'debian')
                command.assert_not_called()

    def test_firewall_failure_stops_instead_of_silently_continuing(self):
        args = build_parser().parse_args([])
        with patch.object(installer, 'run_cmd', side_effect=DeploymentError('missing')) as command:
            with self.assertRaisesRegex(DeploymentError, 'partially applied'):
                installer.setup_firewall(args, 'rocky', 'rhel')
            self.assertEqual(command.call_count, 1)

    def test_unsupported_distro_requires_explicit_skip(self):
        with self.assertRaisesRegex(DeploymentError, '--skip-firewall'):
            installer.setup_firewall(build_parser().parse_args([]), 'arch', '')

    def test_dry_run_prints_plan_without_executing_commands(self):
        args = build_parser().parse_args(['--dry-run', '--port', '8443'])
        output = io.StringIO()
        with patch.object(installer, 'run_cmd') as command, redirect_stdout(output):
            installer.setup_firewall(args, 'rocky', 'rhel')
            command.assert_not_called()
        self.assertIn('if inactive', output.getvalue())
        self.assertIn('[dry-run] firewall-cmd --add-port=8443/tcp', output.getvalue())
        self.assertIn('[dry-run] firewall-cmd --permanent --add-port=8443/tcp', output.getvalue())

    def test_firewall_failure_prevents_config_replacement(self):
        args = build_parser().parse_args(['--dry-run', '--skip-upgrade'])
        with patch.object(installer, 'setup_firewall', side_effect=DeploymentError('firewall failed')), \
                patch.object(installer, 'write_config') as write, redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(DeploymentError, 'firewall failed'):
                installer.deploy(args)
            write.assert_not_called()


class RunCommandBehaviorTests(unittest.TestCase):
    def test_run_cmd_missing_binary_with_check_false_returns_nonzero_result(self):
        result = run_cmd(["definitely-not-a-real-command-123"], check=False)
        self.assertEqual(result.returncode, 127)
        self.assertEqual(result.stdout, "")

    def test_run_cmd_missing_binary_with_check_true_raises_deployment_error(self):
        with self.assertRaises(DeploymentError):
            run_cmd(["definitely-not-a-real-command-123"], check=True)

    def test_run_cmd_missing_xray_includes_install_hint(self):
        with self.assertRaisesRegex(DeploymentError, r"install xray first"):
            run_cmd(["xray", "-test", "-config", "/tmp/xray.json"], check=True)

    def test_command_not_found_hint_for_systemctl(self):
        self.assertIn("systemd-based Linux", command_not_found_hint("systemctl"))


class ClientProfileOutputTests(unittest.TestCase):
    def test_print_client_profile_includes_config_path_and_save_reminder(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            print_client_profile(
                server_ip="1.2.3.4",
                port=443,
                uuid="u-1",
                server_name="www.microsoft.com",
                public_key="pub",
                short_id="6baad05011122233",
                config_path="/usr/local/etc/xray/config.json",
                config_written="yes",
            )
        output = buffer.getvalue()
        self.assertIn("ConfigPath: /usr/local/etc/xray/config.json", output)
        self.assertIn("ConfigWritten: yes", output)
        self.assertIn("请务必将这些信息妥善保存，客户端连接时需要用到。", output)


class ParserTests(unittest.TestCase):
    def test_parser_accepts_verbose_flag(self):
        args = build_parser().parse_args(["--verbose"])
        self.assertTrue(args.verbose)


class ExistingConfigHandlingTests(unittest.TestCase):
    def test_handle_existing_config_abort_when_user_declines(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text('{"inbounds":[{"port":443}]}', encoding="utf-8")
            with patch("builtins.input", return_value="n"):
                with self.assertRaisesRegex(DeploymentError, r"aborted by user"):
                    handle_existing_config(config_path, dry_run=False, assume_yes=False)
            backups = list(Path(tmpdir).glob("config.json.*"))
            self.assertEqual(backups, [])

    def test_handle_existing_config_backup_when_user_accepts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            original = {"inbounds": [{"port": 443}]}
            config_path.write_text(json.dumps(original), encoding="utf-8")
            with patch("builtins.input", return_value="y"):
                handle_existing_config(config_path, dry_run=False, assume_yes=False)
            backups = list(Path(tmpdir).glob("config.json.*"))
            self.assertEqual(len(backups), 1)
            backup_content = json.loads(backups[0].read_text(encoding="utf-8"))
            self.assertEqual(backup_content["inbounds"][0]["port"], 443)



class SecurityTests(unittest.TestCase):
    def test_short_id_requires_even_length(self):
        for value in ['123456789', '123456789ab', 'ABCDEF12', '', 'a' * 18]:
            with self.subTest(value=value), self.assertRaises(DeploymentError):
                installer.validate_short_id(value)
        for length in [8, 10, 12, 14, 16]:
            self.assertEqual(len(installer.generate_short_id(length)), length)
        with self.assertRaises(DeploymentError):
            installer.generate_short_id(9)

    def test_target_port_is_independent_of_listener(self):
        config = build_xray_config(port=8443, uuid='test', server_name='example.com',
                                   private_key='secret', short_id='0123456789abcdef')
        inbound = config['inbounds'][0]
        self.assertEqual(inbound['streamSettings']['realitySettings']['target'], 'example.com:443')
        self.assertEqual(inbound['streamSettings']['network'], 'raw')
        self.assertEqual(config['routing']['domainStrategy'], 'IPOnDemand')
        self.assertIn('169.254.0.0/16', config['routing']['rules'][0]['ip'])
        self.assertIn('fc00::/7', config['routing']['rules'][0]['ip'])
        self.assertNotIn('limitFallbackDownload', inbound['streamSettings']['realitySettings'])

    def test_invalid_options_fail_before_deployment(self):
        for options in [['--port', '0'], ['--port', '65536'], ['--uuid', 'invalid'],
                        ['--server-name', '*.example.com'], ['--server-name', '127.0.0.1'],
                        ['--target', 'https://example.com:443'], ['--target', 'example.com'],
                        ['--target', 'user@example.com:443'], ['--config-path', '/tmp/config.json']]:
            with self.subTest(options=options), self.assertRaises(DeploymentError):
                installer.validate_options(build_parser().parse_args(options))
        installer.validate_options(build_parser().parse_args([]))
        self.assertEqual(installer.parse_target('[2001:db8::1]:443'), ('2001:db8::1', 443))

    def test_sensitive_output_is_hidden_on_success_and_failure(self):
        result = CommandResult('PRIVATE_SECRET', 'PRIVATE_SECRET', 0)
        buffer = io.StringIO()
        with patch.object(installer, 'run_cmd', return_value=result), redirect_stdout(buffer):
            installer.maybe_run(['xray', 'x25519'], dry_run=False, verbose=True, sensitive=True)
        self.assertNotIn('PRIVATE_SECRET', buffer.getvalue())
        process = subprocess.CompletedProcess(['xray'], 1, 'PRIVATE_SECRET', 'PRIVATE_SECRET')
        with patch.object(installer.subprocess, 'run', return_value=process):
            with self.assertRaises(DeploymentError) as error:
                run_cmd(['xray'], sensitive=True)
        self.assertNotIn('PRIVATE_SECRET', str(error.exception))
        with self.assertRaises(DeploymentError) as error:
            parse_x25519_output('PRIVATE_SECRET')
        self.assertNotIn('PRIVATE_SECRET', str(error.exception))

    def test_invalid_candidate_keeps_old_file_and_removes_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_bytes(b'original')
            with patch.object(installer, 'run_cmd', side_effect=DeploymentError('invalid')):
                with self.assertRaises(DeploymentError):
                    installer.write_config(path, {'privateKey': 'secret'}, False, service_user='xray')
            self.assertEqual(path.read_bytes(), b'original')
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_candidate_has_json_suffix_before_service_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'

            def validate(command, **kwargs):
                candidate = Path(command[-1])
                self.assertEqual(candidate.suffix, '.json')
                self.assertEqual(json.loads(candidate.read_text()), {'log': {'loglevel': 'warning'}})
                self.assertFalse(path.exists())
                return CommandResult('Configuration OK.', '', 0)

            with patch.object(installer, 'run_cmd', side_effect=validate):
                installer.write_config(path, {'log': {'loglevel': 'warning'}}, False, service_user='xray')
            self.assertTrue(path.exists())
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_validation_error_retains_diagnostics_without_credentials(self):
        config = {'inbounds': [{'settings': {'clients': [{'id': 'UUID_SECRET'}]},
                  'streamSettings': {'realitySettings': {
                      'privateKey': 'PRIVATE_SECRET', 'shortIds': ['SHORT_SECRET'],
                      'password': 'PASSWORD_SECRET', 'mldsa65Seed': 'MLDSA_SECRET',
                  }}}]}
        output = 'permission denied: UUID_SECRET PRIVATE_SECRET SHORT_SECRET PASSWORD_SECRET MLDSA_SECRET'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_bytes(b'original')
            with patch.object(installer, 'run_cmd', return_value=CommandResult(output, output, 23)):
                with self.assertRaises(DeploymentError) as error:
                    installer.write_config(path, config, False, service_user='xray')
            message = str(error.exception)
            self.assertIn('permission denied', message)
            self.assertIn('exit=23', message)
            self.assertIn('service user xray', message)
            self.assertNotIn('_SECRET', message)
            self.assertEqual(path.read_bytes(), b'original')
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_config_and_backup_have_restricted_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            installer.write_config(path, {'privateKey': 'secret'}, False)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            with redirect_stdout(io.StringIO()):
                backup = handle_existing_config(path, dry_run=False, assume_yes=True)
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertEqual(backup.read_bytes(), path.read_bytes())
            path.unlink()
            path.symlink_to(backup)
            with self.assertRaises(DeploymentError):
                handle_existing_config(path, dry_run=False, assume_yes=True)

    def test_old_version_is_rejected_when_installation_is_disabled(self):
        args = build_parser().parse_args(['--skip-install-xray'])
        with patch.object(installer, 'run_cmd', return_value=CommandResult('Xray 25.9.5', '', 0)):
            with self.assertRaisesRegex(DeploymentError, 'required'):
                installer.ensure_xray_installed(args)

    def test_newer_and_prerelease_versions_are_not_silently_accepted(self):
        args = build_parser().parse_args([])
        for version in ['27.1.1', '26.10.31-beta']:
            with self.subTest(version=version), \
                    patch.object(installer, 'run_cmd', return_value=CommandResult(f'Xray {version}', '', 0)), \
                    patch.object(installer.urllib.request, 'urlopen') as download:
                with self.assertRaises(DeploymentError):
                    installer.ensure_xray_installed(args)
                download.assert_not_called()

    def test_bbr_must_actually_take_effect(self):
        args = build_parser().parse_args([])
        with patch.object(installer, 'ensure_sysctl_line'), \
                patch.object(installer, 'maybe_run'), \
                patch.object(installer, 'run_cmd', return_value=CommandResult('cubic', '', 0)):
            with self.assertRaisesRegex(DeploymentError, 'BBR did not take effect'):
                installer.setup_bbr(args, 'ubuntu', 'debian')

    def test_target_certificate_failure_stops_preflight(self):
        with patch.object(installer.ssl, 'create_default_context') as context, \
                patch.object(installer.socket, 'create_connection'):
            context.return_value.wrap_socket.side_effect = installer.ssl.SSLCertVerificationError('mismatch')
            with self.assertRaisesRegex(DeploymentError, 'preflight failed'):
                installer.check_reality_target('example.com', 'example.com:443', False)

    def test_installer_checksum_mismatch_never_executes(self):
        args = build_parser().parse_args([])
        with patch.object(installer, 'run_cmd', return_value=CommandResult('', '', 127)), \
                patch.object(installer.urllib.request, 'urlopen', return_value=io.BytesIO(b'tampered')), \
                patch.object(installer, 'maybe_run') as execute:
            with self.assertRaisesRegex(DeploymentError, 'SHA256 mismatch'):
                installer.ensure_xray_installed(args)
            execute.assert_not_called()

    def test_pinned_install_and_post_install_version_check(self):
        args = build_parser().parse_args([])
        script = b'verified script'
        with patch.object(installer, 'run_cmd', side_effect=[CommandResult('Xray 25.9.5', '', 0),
                    CommandResult(f'Xray {installer.XRAY_VERSION}', '', 0)]), \
                patch.object(installer.urllib.request, 'urlopen', return_value=io.BytesIO(script)), \
                patch.object(installer, 'INSTALL_SHA256', hashlib.sha256(script).hexdigest()), \
                patch.object(installer, 'maybe_run') as execute:
            installer.ensure_xray_installed(args)
        command = execute.call_args.args[0]
        self.assertIn(f'v{installer.XRAY_VERSION}', command)
        self.assertIn('--manually-restart-later', command)

    def test_service_must_be_non_root_and_use_the_expected_config(self):
        account = SimpleNamespace(pw_uid=1001, pw_gid=1001)
        with patch.object(installer.pwd, 'getpwnam', return_value=account), \
                patch.object(installer.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=1001)):
            for user, command in [('root', 'unused'), ('xray', 'wrong path')]:
                if user == 'root':
                    account.pw_uid = 0
                else:
                    account.pw_uid = 1001
                with patch.object(installer, 'run_cmd', side_effect=[CommandResult(user, '', 0),
                            CommandResult('xray', '', 0), CommandResult(command, '', 0)]):
                    with self.assertRaises(DeploymentError):
                        installer.get_service_identity()

    def test_target_rejects_missing_h2_and_http_redirects(self):
        for alpn, status in [(None, 200), ('h2', 302)]:
            with self.subTest(alpn=alpn, status=status), \
                    patch.object(installer.ssl, 'create_default_context') as context, \
                    patch.object(installer.socket, 'create_connection'), \
                    patch.object(installer.http.client, 'HTTPResponse') as response:
                tls = context.return_value.wrap_socket.return_value.__enter__.return_value
                tls.selected_alpn_protocol.return_value = alpn
                response.return_value.status = status
                with self.assertRaises(DeploymentError):
                    installer.check_reality_target('example.com', 'example.com:443', False)


class RealityKeyExchangeTests(unittest.TestCase):
    @staticmethod
    def ping_output(group):
        return (
            "TLS ping: example.com\n"
            "Pinging without SNI\n"
            f"TLS Version: TLS 1.3\nTLS Post-Quantum key exchange: false ({group})\n"
            "Pinging with SNI\n"
            "Handshake succeeded\n"
            f"TLS Version: TLS 1.3\nTLS Post-Quantum key exchange: false ({group})\n"
        )

    def test_parse_accepts_x25519_groups(self):
        for group in ['X25519', 'X25519MLKEM768']:
            with self.subTest(group=group):
                self.assertEqual(installer.parse_reality_ping_group(self.ping_output(group)), group)

    def test_check_rejects_non_x25519_target(self):
        with patch.object(installer.Path, 'exists', return_value=True), \
                patch.object(installer.subprocess, 'run',
                             return_value=subprocess.CompletedProcess([], 0, self.ping_output('CurveP384'), '')):
            with self.assertRaisesRegex(DeploymentError, 'CurveP384'):
                installer.check_reality_key_exchange('example.com', 'example.com:443', False)

    def test_check_fails_on_ping_error(self):
        with patch.object(installer.Path, 'exists', return_value=True), \
                patch.object(installer.subprocess, 'run',
                             return_value=subprocess.CompletedProcess([], 1, '', 'handshake failed')):
            with self.assertRaisesRegex(DeploymentError, 'exit=1'):
                installer.check_reality_key_exchange('example.com', 'example.com:443', False)

    def test_dry_run_does_not_execute_ping(self):
        with patch.object(installer.subprocess, 'run') as ping, redirect_stdout(io.StringIO()):
            installer.check_reality_key_exchange('example.com', 'example.com:443', True)
            ping.assert_not_called()

    def test_dry_run_adds_only_listener_tcp_rule_and_hides_private_key(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            installer.deploy(build_parser().parse_args(['--dry-run', '--print-config', '--skip-upgrade']))
        output = buffer.getvalue()
        self.assertIn('[dry-run] ufw allow 443/tcp', output)
        self.assertNotIn('443/udp', output)
        self.assertNotIn('firewall-cmd', output)
        self.assertNotIn('<PRIVATE_KEY>', output)
        self.assertIn('<REDACTED>', output)
        self.assertIn(installer.DEFAULT_SERVER_NAME, output)

    def test_restart_failure_restores_exact_previous_bytes(self):
        cases = [(old, step) for old in [b'{"inbounds":[]}\n', None]
                 for step in ['restart', 'is-active']]
        for original, failure in cases:
            with self.subTest(original=original, failure=failure), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'config.json'
                if original is not None:
                    path.write_bytes(original)
                restarts = []

                def command(cmd, **kwargs):
                    if cmd[-1] == 'x25519':
                        return CommandResult('PrivateKey: SECRET\nPassword: PUBLIC', '', 0)
                    if cmd[:2] == ['systemctl', 'restart']:
                        restarts.append(cmd)
                        if failure == 'restart' and len(restarts) == 1:
                            raise DeploymentError('restart failed')
                    if cmd[:2] == ['systemctl', 'is-active'] and failure == 'is-active':
                        raise DeploymentError('service exited')
                    return CommandResult('', '', 0)

                args = build_parser().parse_args(['--yes', '--skip-upgrade', '--skip-bbr', '--skip-firewall'])
                args.config_path = str(path)
                with patch.object(installer, 'XRAY_CONFIG_DEFAULT', str(path)), \
                        patch.object(installer, 'ensure_root_or_die'), \
                        patch.object(installer, 'check_reality_target'), \
                        patch.object(installer, 'check_reality_key_exchange'), \
                        patch.object(installer, 'ensure_xray_installed'), \
                        patch.object(installer, 'get_service_identity', return_value=('xray', os.getgid())), \
                        patch.object(installer.os, 'chown'), \
                        patch.object(installer.time, 'sleep'), \
                        patch.object(installer, 'run_cmd', side_effect=command), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaises(DeploymentError):
                        installer.deploy(args)
                if original is None:
                    self.assertFalse(path.exists())
                else:
                    self.assertEqual(path.read_bytes(), original)
                    self.assertEqual(len(restarts), 2)




class StableCoreIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("XRAY_TEST_BINARY"), "set XRAY_TEST_BINARY to a verified stable binary")
    def test_current_stable_generates_keys_and_accepts_config(self):
        binary = os.environ["XRAY_TEST_BINARY"]
        version = subprocess.run([binary, "version"], check=True, capture_output=True, text=True)
        self.assertTrue(version.stdout.startswith(f"Xray {installer.XRAY_VERSION} "))
        result = subprocess.run([binary, "x25519"], check=True, capture_output=True, text=True)
        keys = parse_x25519_output(result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            config = build_xray_config(
                port=8443, uuid="5783a3e7-e373-51cd-8642-c83782b807c5",
                server_name=installer.DEFAULT_SERVER_NAME, private_key=keys["private_key"],
                short_id=installer.generate_short_id(),
            )
            original_run_cmd = installer.run_cmd

            def validate_staged_config(command, **kwargs):
                self.assertEqual(command[:3], ["runuser", "-u", "xray"])
                binary_index = command.index("--") + 1
                # Run the real core as the test user; changing users requires root.
                return original_run_cmd(command[binary_index:], **kwargs)

            with patch.object(installer, "XRAY_BINARY", binary), \
                    patch.object(installer, "run_cmd", side_effect=validate_staged_config):
                installer.write_config(path, config, False, service_user="xray")
            self.assertTrue(path.exists())
            self.assertEqual(list(Path(directory).iterdir()), [path])



if __name__ == "__main__":
    unittest.main()
