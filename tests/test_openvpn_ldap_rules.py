#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from openvpn_ldap.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Jan 28 14:25:49 VPN-SERVER-05892 openvpn: LDAP bind failed: Invalid credentials (80090308: LdapErr: DSID-55555555, comment: AcceptSecurityContext error, data 775, v3839)',
            'openvpn',
            '81805',
            5,
            id='openvpn_ldap_bind_failed',
        ),
        pytest.param(
            'Jan 28 14:25:49 VPN-SERVER-05892 openvpn: Incorrect password supplied for LDAP DN "CN=Harry T. Hacker,OU=business unit,OU=department,DC=domain,DC=com"',
            'openvpn',
            '81806',
            5,
            id='openvpn_ldap_logon_failure',
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


