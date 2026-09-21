#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from cpanel.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""[2016-04-18 13:07:02 -0400] info [cpsrvd] 10.1.5.19 - root - SUCCESS LOGIN whostmgrd""",
            'postgresql_log',
            '11007',
            3,
            id='successful_login_1',
        ),
        pytest.param(
            r"""[2016-04-18 13:07:15 -0400] info [cpsrvd] 10.1.5.19 - reseller (possessor: root) - SUCCESS LOGIN cpaneld""",
            'postgresql_log',
            '11007',
            3,
            id='successful_login_2',
        ),
        pytest.param(
            r"""[2016-04-18 13:08:27 -0400] info [cpsrvd] 10.1.5.19 - emailaccount@reseller.com (possessor: reseller) - SUCCESS LOGIN webmaild""",
            'postgresql_log',
            '11007',
            3,
            id='successful_login_3',
        ),
        pytest.param(
            r"""[2017-01-25 06:01:10 -0500] info [cpsrvd] 10.1.5.19 - test "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN cpaneld: invalid cpanel user test (loadcpdata failed)""",
            'postgresql_log',
            '11001',
            5,
            id='cpanel_attacks',
        ),
        pytest.param(
            r"""[2016-11-18 09:32:19 +0000] info [cpsrvd] 10.1.5.19 - admin "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN whostmgrd: user password hash is missing from system (user probably does not exist)""",
            'cpanel-login',
            '11000',
            5,
            id='cpanel_attacks_2',
        ),
        pytest.param(
            r"""[2016-04-18 13:07:02 +0400] info [cpsrvd] 10.1.5.19 - root - SUCCESS LOGIN whostmgrd""",
            'cpanel-login',
            '11006',
            3,
            id='successful_login_2',
        ),
        pytest.param(
            r"""[2017-01-25 06:15:38 -0500] info [cpsrvd] 10.1.5.19 PURGE root:Nmm4xzhSpA2Sddv3 logout""",
            'postgresql_log',
            '11009',
            3,
            id='session_purge',
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


