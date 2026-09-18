#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from nginx.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '2014/12/30 06:07:37 [yadda] 80:2 yadda yadda',
            'nginx-errorlog',
            '31300',
            0,
            id='nginx_messages_grouped',
        ),
        pytest.param(
            '2014/12/30 06:07:37 [error] 80:2 yadda yadda',
            'nginx-errorlog',
            '31301',
            3,
            id='nginx_error_message',
        ),
        pytest.param(
            '2014/12/30 06:07:37 [warn] 80:2 yadda yadda',
            'nginx-errorlog',
            '31302',
            3,
            id='nginx_warning_message',
        ),
        pytest.param(
            '2014/12/30 06:07:37 [crit] 80:2',
            'nginx-errorlog',
            '31303',
            5,
            id='nginx_critical_message',
        ),
        pytest.param(
            '2015/01/08 11:31:23 [error] 80:2 blah blah failed (2: No such file or directory)',
            'nginx-errorlog',
            '31310',
            0,
            id='server_returned_404_reported_in_the_access_log_1',
        ),
        pytest.param(
            '2015/01/08 11:31:23 [error] 80:2 blah blah is not found (2: No such file or directory)',
            'nginx-errorlog',
            '31310',
            0,
            id='server_returned_404_reported_in_the_access_log_2',
        ),
        pytest.param(
            '2015/01/08 11:31:23 [error] 80:2 blah blah accept() failed (53: Software caused connection abort)',
            'nginx-errorlog',
            '31311',
            0,
            id='incomplete_client_request',
        ),
        pytest.param(
            '2015/01/08 11:31:23 [error] 80:2 no user/password was provided for basic authentication',
            'nginx-errorlog',
            '31312',
            0,
            id='initial_401_authentication_request',
        ),
        pytest.param(
            '2015/01/08 11:31:23 [error] 80:2 yadda password mismatch, client yadda',
            'nginx-errorlog',
            '31315',
            5,
            id='web_authentication_failed_1',
        ),
        pytest.param(
            '2015/01/08 11:31:23 [error] 80:2 yadda was not found in yadda',
            'nginx-errorlog',
            '31315',
            5,
            id='web_authentication_failed_2',
        ),
        pytest.param(
            '2015/01/08 11:31:23 [crit] 80:2 yadda yadda failed (2: No such file or directory',
            'nginx-errorlog',
            '31317',
            0,
            id='common_cache_error_when_files_were_removed',
        ),
        pytest.param(
            '2015/01/08 11:31:23 [error] 80:2 yadda yadda failed (36: File name too long)',
            'nginx-errorlog',
            '31320',
            10,
            id='invalid_uri_file_name_too_long',
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


