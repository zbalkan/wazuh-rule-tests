#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from glpi.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""[Wed Jul 31 16:44:52.906254 2019] [suexec:notice] [pid 8575] AH01232: suEXEC mechanism enabled (wrapper: /usr/sbin/suexec)""",
            'apache-errorlog',
            '30303',
            0,
            id='apache_glpi_error_log',
        ),
        pytest.param(
            r'''11.0.0.1 - - [31/Jul/2019:16:58:19 +0000] "GET /index.php HTTP/1.1" 200 2213 "http://11.0.0.16/install/install.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"''',
            'web-accesslog',
            '31108',
            0,
            id='web_accesslog_glpi_get_message',
        ),
        pytest.param(
            r'''::1 - - [31/Jul/2019:16:58:43 +0000] "OPTIONS * HTTP/1.0" 200 - "-" "Apache/2.4.6 (CentOS) PHP/5.6.40 (internal dummy connection)"''',
            'web-accesslog',
            '31108',
            0,
            id='web_accesslog_glpi_options_message',
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


