#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from systemd.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""Jul 19 07:28:02 localhost systemd: Failed to mark scope session-1024.scope as abandoned : Stale file handle""",
            'systemd',
            '40701',
            0,
            id='stale_file_handle',
        ),
        pytest.param(
            r"""Aug 13 13:20:58 master systemd: Time has been changed""",
            'systemd',
            '40705',
            5,
            id='system_time_changed',
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


