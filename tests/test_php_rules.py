#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from php.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '2014/12/30 06:07:37 [error] PHP Warning: urlencode() expects parameter 1 to be string, array given in',
            'nginx-errorlog',
            '31411',
            6,
            id='php_web_attack',
        ),
        pytest.param(
            "2014/12/30 06:07:37 [error] PHP Fatal error:  require_once() [<a href='function.require'>function.require</a>]: Failed opening required 'includes/SkinTemplate.php'",
            'nginx-errorlog',
            '31421',
            5,
            id='php_internal_error_missing_file_or_function',
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


