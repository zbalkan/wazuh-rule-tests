#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from openldap.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=0 BIND dn="uid=example,ou=People,dc=example,dc=com" method=128',
            'openldap',
            '2507',
            0,
            id='openldap_generic_1',
        ),
        pytest.param(
            'Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=0 RESULT tag=97 err=49 text=',
            'openldap',
            '2507',
            0,
            id='openldap_generic_2',
        ),
        pytest.param(
            'Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=1 BIND dn="uid=example,ou=People,dc=example,dc=com" method=128',
            'openldap',
            '2507',
            0,
            id='openldap_generic_3',
        ),
        pytest.param(
            'Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=1 RESULT tag=97 err=0 text=',
            'openldap',
            '2507',
            0,
            id='openldap_generic_4',
        ),
        pytest.param(
            'Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=2 UNBIND',
            'openldap',
            '2507',
            0,
            id='openldap_generic_5',
        ),
        pytest.param(
            'Jan 11 09:26:57 hostname slapd[20872]: conn=999999 fd=64',
            'openldap',
            '2507',
            0,
            id='openldap_generic_6',
        ),
        pytest.param(
            'Jan 11 09:26:57 hostname slapd[20872]: conn=999999 fd=64 ACCEPT from IP=10.10.248.27:33957 (IP=10.10.241.77:389)',
            'openldap',
            '2508',
            3,
            id='openldap_connection_open_1',
        ),
        pytest.param(
            'Oct  2 19:51:22 example slapd[30864]: conn=1068 fd=19 ACCEPT from IP=192.168.0.2:59800 (IP=0.0.0.0:636)',
            'openldap',
            '2508',
            3,
            id='openldap_connection_open_2',
        ),
        pytest.param(
            'Feb 11 20:12:27 ldap slapd[13129]: conn=15098 fd=23 ACCEPT from IP=[fda2:3ab6:adf4:aa2a::0]:45242 (IP=[::]:389)',
            'openldap',
            '2508',
            3,
            id='openldap_connection_open_3',
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


