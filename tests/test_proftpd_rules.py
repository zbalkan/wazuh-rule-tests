#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from proftpd.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Jan 04 22:51:57 server proftpd[26169] server.example.net: Fatal: unable to open incoming connection: Der Socket ist nicht verbunden',
            'proftpd',
            '11222',
            4,
            id='unable_to_open_incoming_connection_reason_may_vary',
        ),
        pytest.param(
            'Jan 04 22:51:57 hayaletgemi proftpd[26916]: hayaletgemi (85.101.218.135[85.101.218.135]) - ANON anonymous: Login successful.',
            'proftpd',
            '11205',
            3,
            id='ftp_authentication_success_1',
        ),
        pytest.param(
            'Jan 04 22:51:57 juf01 proftpd[12564]: juf01 (pD9EE35B1.dip.t-dialin.net[217.238.53.177]) - USER jufu: Login successful',
            'proftpd',
            '11205',
            3,
            id='ftp_authentication_success_2',
        ),
        pytest.param(
            'Jan 04 22:51:57 xx.yy.zz proftpd[30362] xx.yy.zz (aa.bb.cc[aa.bb.vv.dd]): USER backup: Login successful.',
            'proftpd',
            '11205',
            3,
            id='ftp_authentication_success_3',
        ),
        pytest.param(
            'Jan 04 22:51:57 server proftpd[2344]: refused connect from 192.168.1.2 (192.168.1.2)',
            'proftpd',
            '11207',
            5,
            id='connection_refused_by_tcp_wrappers',
        ),
        pytest.param(
            'Jan 04 22:51:57 valhalla proftpd[15181]: valhalla (crawl-66-249-66-80.googlebot.com[66.249.66.80]) - Connection from crawl-66-249-66-80.googlebot.com [66.249.66.80] denied.',
            'proftpd',
            '11206',
            5,
            id='connection_denied_by_proftpd_configuration',
        ),
        pytest.param(
            '2015-04-16 21:51:02,805 zuse proftpd[26189] zuse.domain.com (182.100.67.115[182.100.67.115]): USER root (Login failed): Incorrect password',
            'proftpd',
            '11204',
            5,
            id='login_failed_accessing_the_ftp_server',
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


