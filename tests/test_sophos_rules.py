#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from sophos.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""<log><category>savscan.log</category><level>INFO</level><domain>savscan</domain><msg>SAVSCAN-DETAILS %s %s %s %s %s %s</msg><time>1558570140</time><arg>0</arg><arg>0</arg><arg>108267</arg><arg>131</arg><arg>0</arg><arg>0</arg></log>""",
            'sophos-win',
            '64271',
            3,
            id='sophos_win_notice_message_detected',
        ),
        pytest.param(
            r"""<log><category>savscan.log</category><level>INFO</level><domain>savscan</domain><msg>NOTIFY_ONDEMANDTHREAT_INFECTED %s</msg><time>1558572421</time><arg>path_file</arg></log>""",
            'sophos-win',
            '64272',
            6,
            id='sophos_win_notify_ondemandthreat_infected_alert',
        ),
        pytest.param(
            r"""<log><category>savscan.log</category><level>INFO</level><domain>savscan</domain><msg>SCANNER_DIED_KILLED</msg><time>1558572421</time></log>""",
            'sophos-win',
            '64273',
            6,
            id='sophos_win_scanner_died_killed_alert',
        ),
        pytest.param(
            r"""<log><category>update.check</category><level>INFO</level><domain>savupdate</domain><msg>NO_UPDATED_FROM %s</msg><time>1558572421</time><arg>http://10.11.12.13/SophosUpdate/CIDs/S000/EESAVUNIX/SUNOS_9_SPARC</arg></log>""",
            'sophos-win',
            '64275',
            3,
            id='sophos_win_no_updated_from_alert',
        ),
        pytest.param(
            r"""20160806 050000	Scan 'Sophos Cloud Scheduled Scan' started.""",
            'sophos',
            '82101',
            3,
            id='sophos_cloud_scheduled_scan_started',
        ),
        pytest.param(
            r"""20160806 052043	Scan 'Sophos Cloud Scheduled Scan' completed.""",
            'sophos',
            '82102',
            3,
            id='sophos_cloud_scheduled_scan_completed',
        ),
        pytest.param(
            r"""20160805 175034	User (NT AUTHORITY\SYSTEM) has stopped on-access scanning for this machine.""",
            'sophos',
            '82104',
            3,
            id='sophos_av_on_access_scanning_stopped',
        ),
        pytest.param(
            r"""20160805 175143	Using detection data version 5.29 (detection engine 3.65.2). This version can detect 11628132 items.""",
            'sophos',
            '82105',
            3,
            id='sophos_av_database_updated',
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


