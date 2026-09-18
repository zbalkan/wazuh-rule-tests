#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from firewalld.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            "Jul 18 10:51:43 localhost firewalld: 2014-07-18 10:51:43 ERROR: '/sbin/iptables -D INPUT_ZONES -t filter -i enp1s0 -g IN_public' failed: iptables: No chain/target/match by that name.",
            '',
            '40902',
            3,
            id='incorrect_chain_target_match',
        ),
        pytest.param(
            "Jul 18 10:51:43 localhost firewalld: 2014-07-18 10:51:43 ERROR: COMMAND_FAILED: '/sbin/iptables -D INPUT_ZONES -t filter -i enp1s0 -g IN_public' failed: iptables: No chain/target/match by that name.",
            '',
            '40902',
            3,
            id='incorrect_chain_target_match',
        ),
        pytest.param(
            'Jul 18 11:04:51 localhost firewalld: 2014-07-18 11:04:51 ERROR: ZONE_ALREADY_SET',
            '',
            '40903',
            2,
            id='firewalld_zone_already_set',
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


