#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from win-generic_rules.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '{"win":{"system":{"providerName":"Microsoft-Windows-TerminalServices-Gateway","providerGuid":"{4D5AE6A1-C7B8-3E6D-B840-4D8029342E1B}","eventID":"200","version":"0","level":"4","task":"2","opcode":"30","keywords":"0x4020000001000000","systemTime":"2023-01-25T20:56:39.141308000Z","eventRecordID":"84771","processID":"4672","threadID":"1996","channel":"Microsoft-Windows-TerminalServices-Gateway/Operational","computer":"server.domain.com","severityValue":"INFORMATION","message":"The user \\"DOM\\\\user\\", on client computer \\"172.16.63.71\\", met connection authorization policy requirements and was therefore authorized to access the RD Gateway server. The authentication method used was: \\"NTLM\\" and connection protocol used: \\"HTTP\\"."},"eventInfo":{"username":"DOM\\\\user","ipAddress":"172.16.93.71","authType":"NTLM","connectionProtocol":"HTTP","errorCode":"0"}}}',
            'json',
            '64105',
            3,
            id='ts_gateway_login_success',
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


