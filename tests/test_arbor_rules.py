#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from arbor.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""Sep 11 23:23:32 user arbor-networks-aps: Blocked Host: Blocked host xxx.xxx.xxx.xxx at hh:mm by Invalid Packets using TCP/23 (TELNET) destination yyy.yyy.yyy.yyy source port pppp,URL: http://web""",
            'arbor',
            '88801',
            7,
            id='blocked_host_1',
        ),
        pytest.param(
            r"""Sep 11 23:23:32 user arbor-networks-aps: Blocked Host: Blocked host xxx.xxx.xxx.xxx at hh:mm by TCP SYN Flood Detection using TCP/3306 (MYSQL) destination yyy.yyy.yyy.yyy source port ppp,URL: http://web""",
            'arbor',
            '88801',
            7,
            id='blocked_host_2',
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


