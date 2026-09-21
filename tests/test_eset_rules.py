#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from eset.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"Threat_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}""",
            'eset-bsd',
            '42002',
            3,
            id='eset_threat_event_rules_group',
        ),
        pytest.param(
            r"""May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"FirewallAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}""",
            'eset-bsd',
            '42003',
            3,
            id='eset_firewall_aggregated_rules_group',
        ),
        pytest.param(
            r"""May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"HipsAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}""",
            'eset-bsd',
            '42004',
            3,
            id='eset_hips_aggregated_rules_group',
        ),
        pytest.param(
            r"""May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"Audit_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}""",
            'eset-bsd',
            '42005',
            2,
            id='eset_audit_rules_group',
        ),
        pytest.param(
            r"""May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"EnterpriseInspectorAlert_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}""",
            'eset-bsd',
            '42006',
            3,
            id='eset_enterprise_inspector_alert_rules_group',
        ),
        pytest.param(
            r"""May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"HipsAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Warning","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}""",
            'eset-bsd',
            '42007',
            5,
            id='eset_warning_severity',
        ),
        pytest.param(
            r"""May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"HipsAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Error","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}""",
            'eset-bsd',
            '42008',
            7,
            id='eset_error_severity',
        ),
        pytest.param(
            r"""May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"HipsAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Critical","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}""",
            'eset-bsd',
            '42009',
            12,
            id='eset_critical_severity',
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


