#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from mailscanner.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Feb 14 06:29:39 hostname update.bad.phishing.sites: Phishing bad sites list updated',
            '',
            '3752',
            0,
            id='update_phishing',
        ),
    ],
)
def test_rule_does_not_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is not LogtestStatus.Error
    assert (
        response.decoder,
        response.rule_id,
        response.rule_level,
    ) != (
        decoder,
        rule_id,
        rule_level,
    )


