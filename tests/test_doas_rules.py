#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from doas.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Apr 13 08:49:20 ix doas: failed command for ddp2: ls',
            'doas',
            '51554',
            5,
            id='failed_command',
        ),
        pytest.param(
            'Mar 22 07:21:58 ix doas: ddp ran command /bin/ksh as root from /data/ddp/projects/git/sysconf/ossec/rules',
            'doas',
            '51556',
            2,
            id='command_run_as_root',
        ),
        pytest.param(
            'Feb 29 14:58:39 ix doas: failed auth for ddp',
            'doas',
            '51557',
            5,
            id='failed_auth',
        ),
        pytest.param(
            'Aug 13 15:16:40 ix doas: ddp ran command as ddpnfs: ls',
            'doas',
            '51555',
            1,
            id='doas_command_run',
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


