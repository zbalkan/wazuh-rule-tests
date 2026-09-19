#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from pfsense.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Jan 22 18:34:00 filterlog: 65,,,0,vmx1,match,pass,out,4,0x0,,63,21011,0,none,1,icmp,56,192.168.105.11,192.168.105.1,datalength=36',
            'pf',
            '87700',
            0,
            id='pfsense_firewall_generic',
        ),
        pytest.param(
            'Nov  8 12:37:34 pfSense filterlog: 5,,,1000102433,em0,match,block,in,4,0x0,,128,24677,0,none,17,udp,186,10.9.0.119,10.9.0.255,17500,17600,166',
            'pf',
            '87701',
            5,
            id='pfsense_firewall_drop_event',
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


