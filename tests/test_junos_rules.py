#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from junos.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Aug 24 04:58:58 192.168.1.1 junos-ids: 2017-08-24T04:58:58.724Z sis-srx-EUH-03 RT_IDS - RT_SCREEN_IP [junos@1.1.1.1.2.1 attack-name="IP spoofing!" source-address="1.1.1.1" destination-address="1.1.1.1" protocol-id="17" source-zone-name="mpls-untrust" interface-name="xxxx.111" action="drop"]',
            'junos-ids',
            '67101',
            10,
            id='junos_spoofing',
        ),
        pytest.param(
            'Sep 23 13:54:55 192.168.1.1 junos-flow: 2017-09-23T13:54:54.803Z sis-srx-mic-01 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.39 source-address="192.168.1.1" source-port="1080" destination-address="192.168.1.2" destination-port="8010" service-name="junos-dns-udp" protocol-id="17" icmp-type="0" policy-name="Local-Default-Deny" source-zone-name="trust" destination-zone-name="untrust" application="UNKNOWN" nested-application="UNKNOWN" username="N/A" roles="N/A" packet-incoming-interface="intf2.302" encrypted="UNKNOWN" reason="policy deny"]',
            'junos-rt-flow',
            '67103',
            5,
            id='junos_deny_1',
        ),
        pytest.param(
            'Sep 21 15:25:06 192.168.1.1 junos-flow: 2017-09-21T15:25:06.141Z sis-srx-ICP-01 RT_FLOW - FLOW_MCAST_RPF_FAIL [junos@2636.1.1.1.2.39 interface-name="intf1.326" source-address="192.168.1.1" destination-address="192.168.1.2" protocol-name="udp"]',
            'junos-rt-flow',
            '67103',
            5,
            id='junos_deny_2',
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


