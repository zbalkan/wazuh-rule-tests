#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from syslog.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Jul 18 09:21:57 localhost kernel: nouveau E[  PGRAPH][0000:0f:00.0] DATA_ERROR BEGIN_END_ACTIVE',
            '',
            '2944',
            1,
            id='uninteresting_nouveau_error',
        ),
        pytest.param(
            'Jul 18 09:21:57 localhost kernel: nouveau E[  PGRAPH][0000:0f:00.0]  DATA_ERROR',
            '',
            '2944',
            1,
            id='uninteresting_nouveau_error_2',
        ),
        pytest.param(
            "Jul 18 10:51:43 localhost NetworkManager[1366]: <warn> (enp1s0) firewall zone remove failed: (32) COMMAND_FAILED: '/sbin/iptables -D INPUT_ZONES -t filter -i enp1s0 -g IN_public' failed: iptables: No chain/target/match by that name.",
            'NetworkManager',
            '2941',
            3,
            id='incorrect_chain_target_match',
        ),
        pytest.param(
            'Feb  5 13:07:52 plugh rsyslogd-2177: imuxsock begins to drop messages from pid 12105 due to rate-limiting',
            '',
            '2945',
            4,
            id='rsyslog_may_be_dropping_messages_due_to_rate_limiting',
        ),
        pytest.param(
            '2015 Nov 13 13:40:01 ether rsyslogd-2177: imuxsock begins to drop messages from pid 17840 due to rate-limiting',
            '',
            '2945',
            4,
            id='non_standard_syslog_ng_format_with_year',
        ),
        pytest.param(
            "May  4 18:21:10 collectd useradd[15178]: failed adding user 'ansible', data deleted",
            '',
            '5905',
            0,
            id='useradd_failed',
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


