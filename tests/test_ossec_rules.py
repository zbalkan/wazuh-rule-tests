#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from ossec.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Sat May  7 03:17:27 CDT 2011 /var/ossec/active-response/bin/host-deny.sh add - 172.16.0.1 1304756247.60385 31151',
            'ar_log',
            '603',
            3,
            id='ossec_active_response_add_host',
        ),
        pytest.param(
            'Sat May  7 03:17:27 CDT 2011 /var/ossec/active-response/bin/firewall-drop.sh add - 172.16.0.1 1304756247.60385 31151',
            'ar_log',
            '601',
            3,
            id='ossec_active_response_add_firewall',
        ),
        pytest.param(
            'Sat May  7 03:27:57 CDT 2011 /var/ossec/active-response/bin/host-deny.sh delete - 172.16.0.1 1304756247.60385 31151',
            'ar_log',
            '604',
            3,
            id='ossec_active_response_delete_host',
        ),
        pytest.param(
            'Sat May  7 03:27:57 CDT 2011 /var/ossec/active-response/bin/firewall-drop.sh delete - 172.16.0.1 1304756247.60385 31151',
            'ar_log',
            '602',
            3,
            id='ossec_active_response_delete_firewall',
        ),
        pytest.param(
            "2015/01/29 21:09:49 ossec-logcollector(1950): INFO: Analyzing file: '/var/log/httpd/error_log'.",
            'ossec-logcollector',
            '701',
            0,
            id='ossec_logcollector_ignore_informational_messages_at_startup',
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


