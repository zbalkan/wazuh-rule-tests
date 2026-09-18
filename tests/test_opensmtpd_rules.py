#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from opensmtpd.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Aug 14 10:15:25 junction.example.com smtpd[28882]: smtp-in: Failed command on session 1f55bdcdf16e28a3: "MAIL FROM:<root@junction.example.com>  " => 421 4.3.0: Temporary Error',
            'smtpd',
            '53501',
            3,
            id='message_failed',
        ),
        pytest.param(
            'Aug 17 01:26:02 ix smtpd[22704]: smtp-in: New session 08d856b172f69c5c from host ix.example.com [local]',
            'smtpd',
            '53502',
            0,
            id='new_session',
        ),
        pytest.param(
            'Aug 17 01:26:02 ix smtpd[22704]: smtp-in: Accepted message 4296f490 on session 08d856b172f69c5c: from=<root@ix.example.com>, to=<ddp@ix.example.com>, size=1746, ndest=1, proto=ESMTP',
            'smtpd',
            '53504',
            0,
            id='message_accepted',
        ),
        pytest.param(
            'Aug 17 01:26:02 ix smtpd[22704]: smtp-in: Closing session 08d856b172f69c5c',
            'smtpd',
            '53503',
            0,
            id='session_closed',
        ),
        pytest.param(
            'Mar  4 00:11:00 ix smtpd[22421]: smtp-in: Received disconnect from session 427e7493ebe154ae',
            'smtpd',
            '53500',
            0,
            id='disconnect',
        ),
        pytest.param(
            'Mar  4 00:13:55 ix smtpd[22421]: smtp-in: Disconnecting session 427e7497e03518ef: IO error: No SSL error',
            'smtpd',
            '53507',
            2,
            id='no_ssl',
        ),
        pytest.param(
            'Mar  4 00:13:55 ix smtpd[22421]: smtp-in: Started TLS on session 427e749c2e46f809: version=TLSv1.2, cipher=EDH-RSA-DES-CBC3-SHA, bits=112',
            'smtpd',
            '53500',
            0,
            id='started_tls',
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


