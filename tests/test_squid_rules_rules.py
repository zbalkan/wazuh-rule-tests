#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from squid_rules.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '1140701044.525   1231 192.168.1.201 TCP_DENIED/400 1536 GET ahmet - NONE/- text/html',
            'squid-accesslog',
            '35003',
            5,
            id='squid_bad_request_invalid_syntax',
        ),
        pytest.param(
            '1140701230.827    781 192.168.1.210 TCP_DENIED/407 1785 GET http://www.ossec.net oahmet NONE/- text/html',
            'squid-accesslog',
            '35007',
            5,
            id='squid_proxy_authentication_required',
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


