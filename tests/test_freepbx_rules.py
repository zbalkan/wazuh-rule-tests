#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from freepbx.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '[2019-07-25 14:29:19] Asterisk 15.7.3 built by root @ centos-7-31 on a x86_64 running Linux on 2019-07-25 14:15:02 UTC',
            'FreePBX',
            '70007',
            3,
            id='freepbx_1',
        ),
        pytest.param(
            '[2019-Jul-25 14:28:31] [INFO] (libraries/modulefunctions.class.php:2083) - Generating CSS...Done',
            'FreePBX',
            '70005',
            3,
            id='freepbx_2',
        ),
        pytest.param(
            'May 19 00:22:05 freepbx-a pacemakerd[1310]:   notice: crm_add_logfile: Additional logging available in /var/log/cluster/corosync.log',
            'FreePBX',
            '70008',
            3,
            id='freepbx_3',
        ),
        pytest.param(
            "[2019-07-25 14:58:54] ERROR[21763] config_options.c: Unable to load config file 'cel.conf'",
            'FreePBX',
            '70001',
            5,
            id='freepbx_4',
        ),
        pytest.param(
            '[npm-cache] [INFO] [npm] hash of /var/www/html/admin/modules/pm2/node/package.json: fa2348032788d5067b56972347177c79',
            'FreePBX',
            '70006',
            3,
            id='freepbx_5',
        ),
        pytest.param(
            '[2019-Jul-25 14:28:32] [freepbx.INFO]: Deprecated way to add Console commands, adding console commands this way can have negative performance impacts. Please use module.xml. See: https://wiki.freepbx.org/display/FOP/Adding+fwconsole+commands [] []',
            'FreePBX',
            '70005',
            3,
            id='freepbx_6',
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


