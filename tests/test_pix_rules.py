#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from pix.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '%PIX-3-710003: TCP access denied by ACL from 216.39.220.130/54065 to outside:62.192.113.98/ssh',
            'pix',
            '4312',
            4,
            id='pix1_2',
        ),
        pytest.param(
            '%PIX-3-106010: Deny inbound tcp src outside:213.98.79.233/2620 dst dmz:213.98.254.145/135',
            'pix',
            '4312',
            4,
            id='pix1_3',
        ),
        pytest.param(
            '%PIX-7-710002: UDP access permitted from 33.33.33.4/943 to inside:33.33.33.15/snmp',
            'pix',
            '4300',
            0,
            id='pix3_1',
        ),
        pytest.param(
            '%PIX-7-710005: UDP request discarded from <public IP of 525>/4500 to outside:192.168.69.137/4500',
            'pix',
            '4300',
            0,
            id='pix3_2',
        ),
        pytest.param(
            '%PIX-7-710002: TCP access permitted from 10.0.0.1/60749 to db:10.0.0.2/ssh',
            'pix',
            '4300',
            0,
            id='pix3_3',
        ),
        pytest.param(
            '%PIX-6-106015: Deny TCP (no connection) from 161.58.238.151/110 to a.b.c.d/3782 flags RST ACK',
            'pix',
            '4300',
            0,
            id='pix3_4',
        ),
        pytest.param(
            '%PIX-3-106011: Deny inbound (No xlate) udp src outside:192.168.2.1/137',
            'pix',
            '4300',
            0,
            id='pix3_5',
        ),
        pytest.param(
            '%PIX-3-106011: Deny inbound (No xlate) tcp src inside:10.100.7.43/80 dst',
            'pix',
            '4300',
            0,
            id='pix3_6',
        ),
        pytest.param(
            '%PIX-4-106023: Deny tcp src inside:111.11.11.1/2143 dst YYY:172.11.1.11/139 by access-group "inside_inbound"',
            'pix',
            '4313',
            4,
            id='pix5',
        ),
        pytest.param(
            '%PIX-2-106006: Deny inbound UDP from ***/20031 to ***/20031 on',
            'pix',
            '4311',
            5,
            id='pix6_1',
        ),
        pytest.param(
            '%PIX-2-106001: Inbound TCP connection denied from 165.139.46.7/3854 to 165.189.27.70/139 flags',
            'pix',
            '4311',
            5,
            id='pix6_2',
        ),
        pytest.param(
            '%PIX-6-305012: Teardown dynamic UDP translation from inside:1.1.1.1/12 to outside:1.2.1.2/11 duration 0:00:11.',
            'pix',
            '4314',
            0,
            id='pix8_1',
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


@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '%PIX-7-710001: TCP access requested from X.X.X.X/1292 to outside:Y.Y.Y.Y/ssh',
            'pix',
            '4312',
            4,
            id='pix1_1',
        ),
        pytest.param(
            '%PIX-2-106002: protocol Connection denied by outbound list acl_ID src inside_address dest outside_address',
            'pix',
            '4314',
            0,
            id='pix8_2',
        ),
        pytest.param(
            '%PIX-2-106002: udp connection denied by outbound list 30 src 216.53.120.62 138 dest 169.132.10.82 138',
            'pix',
            '4314',
            0,
            id='pix8_3',
        ),
        pytest.param(
            '%PIX-4-400013 IDS:2003 ICMP redirect from 10.4.1.2 to 10.2.1.1 on interface dmz',
            'pix',
            '4314',
            0,
            id='pix8_4',
        ),
        pytest.param(
            '%PIX-3-305005: No translation group found for icmp src outside:x.x.x.x dst inside:x.x.x.x (type 3, code 0)',
            'pix',
            '4314',
            0,
            id='pix8_5',
        ),
        pytest.param(
            '%PIX-6-605005: Login permitted from 192.168.1.2/2953 to inside:192.168.1.1/telnet for user ""',
            'pix',
            '4314',
            0,
            id='pix8_6',
        ),
        pytest.param(
            '%PIX-6-605004: Login denied from 192.168.2.10/32597 to outside:192.168.2.14/ssh for user "root"',
            'pix',
            '4314',
            0,
            id='pix8_7',
        ),
        pytest.param(
            '%PIX-6-305011: Built dynamic UDP translation from inside:192.168.1.2/1026 to outside:192.168.2.14/1163',
            'pix',
            '4314',
            0,
            id='pix8_8',
        ),
        pytest.param(
            '%PIX-6-305011: Built dynamic TCP translation from inside:192.168.1.3/54946 to outside:192.168.2.14/1033',
            'pix',
            '4314',
            0,
            id='pix8_9',
        ),
        pytest.param(
            '%PIX-6-302015: Built outbound UDP connection 156 for outside:192.168.2.10/1514 (192.168.2.10/1514) to inside:192.168.1.2/1026 (192.168.2.14/1163)',
            'pix',
            '4314',
            0,
            id='pix8_10',
        ),
    ],
)
def test_rule_does_not_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is not LogtestStatus.Error
    assert (
        response.decoder,
        response.rule_id,
        response.rule_level,
    ) != (
        decoder,
        rule_id,
        rule_level,
    )


