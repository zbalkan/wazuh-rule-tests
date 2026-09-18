#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from fortiauth.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '2021-07-08T11:01:06-03:00 XXX.XXX.XXX.XXX db[32167]:  category="Event" subcategory="Authentication" typeid=20299 level="information" user="user2" nas="XXX.XXX.XXX.XXX" action="Authentication" status="Pending" Remote RADIUS user authentication partially done, remote server expecting challenge response',
            'fortiauth',
            '44732',
            4,
            id='fortiauth_pending_authentication',
        ),
        pytest.param(
            '2021-07-08T11:00:56-03:00 XXX.XXX.XXX.XXX db[31013]:  category="Event" subcategory="Authentication" typeid=20001 level="information" user="user1" nas="XXX.XXX.XXX.XXX" action="Authentication" status="Failed" Remote RADIUS user authentication with invalid token',
            'fortiauth',
            '44733',
            7,
            id='fortiauth_failed_authentication',
        ),
        pytest.param(
            '2021-07-08T11:00:56-03:00 XXX.XXX.XXX.XXX db[31013]:  category="Event" subcategory="Authentication" typeid=20001 level="information" user="user1" nas="XXX.XXX.XXX.XXX" action="Authentication" status="Success" Remote RADIUS user authentication with no token successful',
            'fortiauth',
            '44734',
            3,
            id='fortiauth_successful_authentication',
        ),
        pytest.param(
            '2021-07-08T11:01:03-03:00 XXX.XXX.XXX.XXX db[32167]:  category="Event" subcategory="System" typeid=30101 level="information" user="admin" nas="" action="" status="" RADIUS server running in full edition',
            'fortiauth',
            '44735',
            4,
            id='fortiauth_info_event',
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


