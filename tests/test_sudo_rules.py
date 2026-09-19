#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from sudo.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Apr 27 15:22:23 niban sudo:     dcid : TTY=pts/4 ; PWD=/home/dcid ; USER=root ; COMMAND=/usr/bin/tail /var/log/snort/alert.fast',
            'sudo',
            '5403',
            4,
            id='sudo_all_1',
        ),
        pytest.param(
            'Apr 14 10:59:01 enigma sudo:     dcid : TTY=ttyp3 ; PWD=/home/dcid/ossec-hids.0.1a/src/analysisd ; USER=root ; COMMAND=/bin/cp -pr ../../bin/addagent ../../bin/osaudit-logaudit ../../bin/ossec-execd ../../bin/ossec-logcollector ../../bin/ossec-maild ../../bin/ossec-remoted /var/ossec/bin',
            'sudo',
            '5403',
            4,
            id='sudo_all_2',
        ),
        pytest.param(
            'Apr 19 14:52:02 enigma sudo:     dcid : TTY=ttyp3 ; PWD=/var/www/alex ; USER=root ; COMMAND=/sbin/chown dcid.dcid .',
            'sudo',
            '5403',
            4,
            id='sudo_all_3',
        ),
        pytest.param(
            'Dec 30 19:36:11 rheltest sudo: cplummer : TTY=pts/2 ; PWD=/home/cplummer1 ; USER=root ; TSID=0000UM ; COMMAND=/bin/bash',
            'sudo',
            '5403',
            4,
            id='sudo_all_4',
        ),
        pytest.param(
            'Jun 25 15:51:13 precise32 sudo:     mike : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/ls',
            'sudo',
            '5401',
            5,
            id='failed_attempt_to_run_sudo',
        ),
        pytest.param(
            'Jun 25 15:48:21 precise32 sudo:  mike : TTY=pts/0 ; PWD=/home/vagrant ; USER=root ; COMMAND=/bin/su -',
            'sudo',
            '5403',
            4,
            id='first_time_user_executed_sudo',
        ),
        pytest.param(
            'Jun 25 16:15:45 precise32 sudo:     mike : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/ls',
            'sudo',
            '5404',
            10,
            id='case_3_incorrect_password_attempts',
        ),
        pytest.param(
            'Apr 13 08:36:31 ix sudo:     ddp2 : user NOT in sudoers ; TTY=ttypZ ; PWD=/home/ddp2 ; USER=root ; COMMAND=/bin/ls',
            'sudo',
            '5405',
            5,
            id='unauthorized_user',
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


