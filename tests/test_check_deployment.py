import unittest

import check_deployment as check


class XrayVersionTests(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(
            check.parse_xray_version("Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff"),
            "26.10.31",
        )
        self.assertEqual(check.parse_xray_version("Xray 25.9.5"), "25.9.5")
        self.assertIsNone(check.parse_xray_version("not xray"))

    def test_version_order(self):
        self.assertLess(check.version_tuple("26.9.30"), check.version_tuple("26.10.31"))
        self.assertEqual(check.version_tuple("26.10.31"), (26, 10, 31))


class UfwStatusTests(unittest.TestCase):
    ACTIVE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
8443                       ALLOW IN    10.0.0.0/8
22/tcp (v6)                ALLOW       Anywhere (v6)
443/tcp (v6)               ALLOW       Anywhere (v6)
"""

    def test_parse_active_rules(self):
        parsed = check.parse_ufw_status(self.ACTIVE)
        self.assertEqual(parsed["status"], "active")
        self.assertIn("deny (incoming)", parsed["default"])
        self.assertEqual(len(parsed["rules"]), 5)

    def test_find_ipv4_and_ipv6_rules(self):
        parsed = check.parse_ufw_status(self.ACTIVE)
        self.assertIsNotNone(check.find_ufw_rule(parsed, 443))
        self.assertIsNotNone(check.find_ufw_rule(parsed, 443, ipv6=True))
        self.assertIsNotNone(check.find_ufw_rule(parsed, 8443))
        self.assertIsNone(check.find_ufw_rule(parsed, 80))
        self.assertIsNone(check.find_ufw_rule(parsed, 8443, ipv6=True))

    def test_parse_inactive(self):
        parsed = check.parse_ufw_status("Status: inactive\n")
        self.assertEqual(parsed["status"], "inactive")
        self.assertEqual(parsed["rules"], [])

    def test_deny_rule_is_not_allow(self):
        parsed = check.parse_ufw_status(
            "Status: active\nDefault: deny (incoming), allow (outgoing)\n"
            "443/tcp                    DENY        Anywhere\n"
        )
        self.assertIsNone(check.find_ufw_rule(parsed, 443))


if __name__ == "__main__":
    unittest.main()
