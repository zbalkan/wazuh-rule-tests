#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from vuln_detector.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '{"vulnerability":{"package":{"name":"ncurses","version":"5.9-14.20130511.el7_4","architecture":"x86_64"},"cve":"CVE-2019-17594", "status":"Solved", "reference":"fb783b1c771a643f81259a93248e7f61e9a4a597"}}',
            'json',
            '23502',
            3,
            id='cve_removed_1',
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


@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '{"vulnerability":{"package":{"name":"ncurses","version":"5.9-14.20130511.el7_4","architecture":"x86_64"},"cve":"", "status":"Solved", "reference":"fb783b1c771a643f81259a93248e7f61e9a4a597"}}',
            'json',
            '23502',
            3,
            id='cve_removed_2',
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


