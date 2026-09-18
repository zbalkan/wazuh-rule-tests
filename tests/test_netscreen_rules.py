#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from netscreen.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '2014-05-23T10:25:58.681222-04:00 10.10.10.1 ssg5-serial: NetScreen device_id=0275112227993284  [Root]system-information-00767: System configuration saved by netscreen via web from host 10.10.10.101 to 10.10.10.1:443 by netscreen. (2014-05-23 10:58:17)',
            'netscreenfw',
            '4509',
            8,
            id='firewall_configuration_changed',
        ),
        pytest.param(
            '2014-05-23T10:29:55.704201-04:00 10.10.10.1 ssg5-serial: NetScreen device_id=0275112227993284  [Root]system-notification-00018: Policy (5, Trust->Untrust, 10.10.10.0/24->172.16.19.0/24,ANY, Permit) was modified by netscreen via web from host 10.10.10.101 to 10.10.10.1:443. (2014-05-23 11:02:13)',
            'netscreenfw',
            '4508',
            8,
            id='firewall_policy_changed',
        ),
        pytest.param(
            '2014-05-23T10:39:20.681154-04:00 10.10.10.1 ssg5-serial: NetScreen device_id=0275112227993284  [Root]system-warning-00515: Management session via SSH from 10.10.10.100:0 for admin netscreen has timed out (2014-05-23 11:11:39)',
            'netscreenfw',
            '4507',
            8,
            id='successfull_admin_login_to_the_netscreen_firewall',
        ),
        pytest.param(
            'Jul  7 05:02:34 ssg5.17.168.192.in-addr.arpa ssg5: NetScreen device_id=ssg5  [Root]system-emergency-00005: SYN flood! From 192.168.18.53:41437 to 192.168.17.251:9612, proto TCP (zone Untrust int  ethernet0/0). Occurred 1 times. (2016-07-07 05:02:32)',
            'netscreenfw',
            '4560',
            3,
            id='syn_flood',
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


