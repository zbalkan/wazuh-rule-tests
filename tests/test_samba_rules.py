#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from samba.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Dec 18 18:06:28 hostname smbd[832]: Denied connection from (192.168.3.23)',
            'smbd',
            '13102',
            5,
            id='samba_denied_connect',
        ),
        pytest.param(
            'Dec 18 18:06:28 hostname smbd[832]: Denied connection from (192.168.3.23)',
            'smbd',
            '13102',
            5,
            id='samba_connect_denied',
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
            'Dec 18 18:06:28 hostname smbd[17535]: Permission denied user not allowed to delete,  pause, or resume print job. User name: ahmet. Printer name: prnq1.',
            'smbd',
            '13102',
            5,
            id='samba_permission_denied_1',
        ),
        pytest.param(
            'Dec 18 18:06:28 hostname smbd[17535]: Permission denied\\-\\- user not allowed to delete,  pause, or resume print job. User name: ahmet. Printer name: prnq1.',
            'smbd',
            '13102',
            5,
            id='samba_permission_denied_2',
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


