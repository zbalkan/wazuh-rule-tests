#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from cisco_ios.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""Sep  1 10:25:29 10.10.10.1 %IPS-4-SIGNATURE: Sig:3051 Subsig:1 Sev:4 TCP Connection Window Size DoS [192.168.100.11:51654 -> 10.10.10.10:4444]""",
            'cisco-ios',
            '20100',
            8,
            id='cisco_ios_ids_sig_1',
        ),
        pytest.param(
            r"""Sep  1 10:25:29 10.10.10.1 %IPS-4-SIGNATURE: Sig:3051 Subsig:1 Sev:4 TCP Connection Window Size DoS [192.168.100.11:60797 -> 10.10.10.10:80]""",
            'cisco-ios',
            '20100',
            8,
            id='cisco_ios_ids_sig_2',
        ),
        pytest.param(
            r"""Sep  1 10:25:29 10.10.10.1 %IPS-4-SIGNATURE: Sig:5123 Subsig:2 Sev:5 WWW IIS Internet Printing Overflow [192.168.100.11:60797 -> 10.10.10.10:80]""",
            'cisco-ios',
            '20100',
            8,
            id='cisco_ios_ids_sig_3',
        ),
        pytest.param(
            r"""Sep  1 10:25:29 10.10.10.1 %SEC-6-IPACCESSLOGP: list 102 denied tcp 10.0.6.56(3067) -> 172.36.4.7(139), 1 packet""",
            'cisco-ios',
            '4716',
            0,
            id='cisco_ios_acl_1',
        ),
        pytest.param(
            r"""Sep  1 10:25:29 10.10.10.1 %SEC-6-IPACCESSLOGP: list 199 denied tcp 10.0.61.108(1477) -> 10.0.127.20(445), 1 packet""",
            'cisco-ios',
            '4716',
            0,
            id='cisco_ios_acl_2',
        ),
        pytest.param(
            r"""3924923: *Oct  6 03:32:04.114 gmt: %SEC-6-IPACCESSLOGP: list bcv_out denied tcp 10.0.3.100(50150) -> 192.168.216.1(443), 1 packet""",
            'cisco-ios',
            '4716',
            0,
            id='cisco_ios_acl_3',
        ),
        pytest.param(
            r"""3924923: *Oct 6 03:32:04 mng: %SEC-6-IPACCESSLOGP: list 1111 denied tcp 10.0.3.100(50150) (Serial4/3 ) -> 192.168.216.1(443), 1 packet""",
            'cisco-ios',
            '4716',
            0,
            id='cisco_ios_acl_4',
        ),
        pytest.param(
            r"""681: Aug 17 17:41:24.776 AEST: %SEC-6-IPACCESSLOGP: list 102 denied tcp 10.0.6.56(3067) -> 172.36.4.7(139), 1 packet""",
            'cisco-ios',
            '4716',
            0,
            id='cisco_ios_acl_5',
        ),
        pytest.param(
            r"""4425: Aug 23 00:17:55.356: %SSH-5-SSH2_SESSION: SSH2 Session request from x.x.x.x (tty = 0) using crypto cipher 'aes-111-sdf0', hmac 'hmac-sha1' Succeeded""",
            'cisco-ios',
            '4715',
            0,
            id='cisco_ios_cisco_switch_1',
        ),
        pytest.param(
            r"""4423: Aug 23 00:16:18.200: %SSH-5-SSH2_USERAUTH: User 'user' authentication for SSH2 Session from x.x.x.x (tty = 0) using crypto cipher 'aes111-sdf0', hmac 'hmac-sha1' Succeeded""",
            'cisco-ios',
            '4715',
            0,
            id='cisco_ios_cisco_switch_2',
        ),
        pytest.param(
            r"""Apr 30 15:10:58: %DOT1X-5-FAIL: Authentication failed for client (Unknown MAC) on Interface Fa0/3 AuditSessionID`""",
            'cisco-ios',
            '4715',
            0,
            id='cisco_ios_cisco_switch_3',
        ),
        pytest.param(
            r"""2019 May 06 09:28:12 vm-ubuntu16->10.0.0.16 May 6 07:28:11 vm-ubuntu16 fortinet Apr 30 15:10:58: %DOT1X-5-FAIL: Authentication failed for client (Unknown MAC) on Interface Fa0/3 AuditSessionID""",
            'cisco-ios',
            '4715',
            0,
            id='cisco_ios_syslog',
        ),
        pytest.param(
            r"""Oct 6 03:32:02 mng: %SEC-6-IPACCESSLOGP: list 1111 denied udp xx.xxx.xx.xx(137) -> xxx.xxx.xxx.xx(137), 1 packet""",
            'cisco-ios',
            '4700',
            0,
            id='cisco_ios_generic_1',
        ),
        pytest.param(
            r"""Oct 6 03:32:02 gmt: %SEC-6-IPACCESSLOGP: list bes_in denied udp xx.xxx.xx.xx(137) (GigabitEthernet0/1.6 ca5c.1da2.ba43) -> xx.xx.xx.xx(137), 1 packet""",
            'cisco-ios',
            '4700',
            0,
            id='cisco_ios_generic_2',
        ),
        pytest.param(
            r"""39222: *Oct 6 03:32:02.070 mng: %SEC-6-IPACCESSLOGP: list 167 denied udp xx.xx.xx.xx(137) (GigabitEthernet0/1.6 ab9c.2a62.aa8d) -> xxx.xxx.xxx.xxx(137), 1 packet""",
            'cisco-ios',
            '4700',
            0,
            id='cisco_ios_generic_3',
        ),
        pytest.param(
            r"""00:00:46: %LINK-3-UPDOWN: Interface Port-channel1, changed state to up""",
            'cisco-ios',
            '4713',
            4,
            id='cisco_ios_error_message_1',
        ),
        pytest.param(
            r"""00:00:47: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to up""",
            'cisco-ios',
            '4713',
            4,
            id='cisco_ios_error_message_2',
        ),
    ],
)
def test_rule_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is LogtestStatus.RuleMatch
    assert response.decoder == decoder
    assert response.rule_id == rule_id
    assert response.rule_level == rule_level


