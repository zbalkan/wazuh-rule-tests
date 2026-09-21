#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from ms-graph.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""{"integration":"ms-graph","ms-graph":{"id":"11111111-2222-3333-4444-555555555555_1","providerAlertId":"11111111-2222-3333-4444-555555555555_1","incidentId":"INC-12345","status":"new","severity":"informational","classification":null,"determination":null,"serviceSource":"microsoftDefenderForEndpoint","detectionSource":"antivirus","productName":"Microsoft Defender for Endpoint","detectorId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","tenantId":"ffffffff-1111-2222-3333-444444444444","title":"'Example' malware was detected","description":"Redacted example description.","recommendedActions":"Redacted example recommendations.","category":"Malware","assignedTo":null,"alertWebUrl":"https://security.microsoft.com/alerts/11111111-2222-3333-4444-555555555555_1?tid=ffffffff-1111-2222-3333-444444444444","incidentWebUrl":"https://security.microsoft.com/incidents/INC-12345/overview?tid=ffffffff-1111-2222-3333-444444444444","actorDisplayName":null,"threatDisplayName":"Trojan:Win32/Example!pz","threatFamilyName":"Example","mitreTechniques":[],"createdDateTime":"2026-01-13T17:30:17.1666667Z","lastUpdateDateTime":"2026-01-13T17:30:54.2633333Z","resolvedDateTime":null,"firstActivityDateTime":"2026-01-13T17:18:53.041636Z","lastActivityDateTime":"2026-01-13T17:18:53.041636Z","systemTags":[],"alertPolicyId":null,"investigationState":"terminatedBySystem","comments":[],"customDetails":{},"evidence":[{"@odata.type":"#microsoft.graph.security.deviceEvidence","createdDateTime":"2026-01-13T17:30:17.4333333Z","verdict":"suspicious","remediationStatus":"active","roles":[],"detailedRoles":["PrimaryDevice"],"tags":[],"firstSeenDateTime":"2025-10-02T15:05:03.9592122Z","mdeDeviceId":"mde-device-id-redacted","azureAdDeviceId":"azuread-device-id-redacted","deviceDnsName":"host.example.internal","hostName":"host","ntDomain":null,"dnsDomain":"example.internal","osPlatform":"Windows","osBuild":12345,"version":"24H2","healthStatus":"active","riskScore":"none","rbacGroupId":0,"rbacGroupName":null,"onboardingStatus":"onboarded","defenderAvStatus":"unknown","lastIpAddress":"192.0.2.10","lastExternalIpAddress":"203.0.113.10","ipInterfaces":[],"vmMetadata":null,"loggedOnUsers":[{"accountName":"user-redacted","domainName":"DOMAIN"}],"resourceAccessEvents":[]},{"@odata.type":"#microsoft.graph.security.fileEvidence","createdDateTime":"2026-01-13T17:30:17.4333333Z","verdict":"malicious","remediationStatus":"active","roles":[],"detailedRoles":[],"tags":[],"detectionStatus":"detected","mdeDeviceId":"mde-device-id-redacted","fileDetails":{"sha1":"sha1-redacted","sha256":"sha256-redacted","md5":"md5-redacted","sha256Ac":null,"fileName":"sample.exe","filePath":"C:\\Users\\user\\Desktop\\sample","fileSize":123456,"filePublisher":null,"signer":null,"issuer":null}}],"additionalData":{},"resource":"security","relationship":"alerts_v2"}}""",
            'json-msgraph',
            '99532',
            12,
            id='msgraph_null_clasification',
        ),
        pytest.param(
            r"""{"integration":"ms-graph","ms-graph":{"id":"11111111-2222-3333-4444-555555555555_2","providerAlertId":"11111111-2222-3333-4444-555555555555_2","incidentId":"INC-12345","status":"new","severity":"informational","classification":"falsePositive","determination":null,"serviceSource":"microsoftDefenderForEndpoint","detectionSource":"antivirus","productName":"Microsoft Defender for Endpoint","detectorId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","tenantId":"ffffffff-1111-2222-3333-444444444444","title":"'Example' malware was detected","description":"Redacted example description.","recommendedActions":"Redacted example recommendations.","category":"Malware","assignedTo":null,"alertWebUrl":"https://security.microsoft.com/alerts/11111111-2222-3333-4444-555555555555_2?tid=ffffffff-1111-2222-3333-444444444444","incidentWebUrl":"https://security.microsoft.com/incidents/INC-12345/overview?tid=ffffffff-1111-2222-3333-444444444444","actorDisplayName":null,"threatDisplayName":"Trojan:Win32/Example!pz","threatFamilyName":"Example","mitreTechniques":[],"createdDateTime":"2026-01-13T17:30:17.1666667Z","lastUpdateDateTime":"2026-01-13T17:30:54.2633333Z","resolvedDateTime":null,"firstActivityDateTime":"2026-01-13T17:18:53.041636Z","lastActivityDateTime":"2026-01-13T17:18:53.041636Z","systemTags":[],"alertPolicyId":null,"investigationState":"terminatedBySystem","comments":[],"customDetails":{},"evidence":[],"additionalData":{},"resource":"security","relationship":"alerts_v2"}}""",
            'json-msgraph',
            '99631',
            3,
            id='msgraph_false_positive',
        ),
        pytest.param(
            r"""{"integration":"ms-graph","ms-graph":{"id":"11111111-2222-3333-4444-555555555555_3","providerAlertId":"11111111-2222-3333-4444-555555555555_3","incidentId":"INC-12345","status":"resolved","severity":"informational","classification":null,"determination":null,"serviceSource":"microsoftDefenderForEndpoint","detectionSource":"antivirus","productName":"Microsoft Defender for Endpoint","detectorId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","tenantId":"ffffffff-1111-2222-3333-444444444444","title":"'Example' malware was detected","description":"Redacted example description.","recommendedActions":"Redacted example recommendations.","category":"Malware","assignedTo":null,"alertWebUrl":"https://security.microsoft.com/alerts/11111111-2222-3333-4444-555555555555_3?tid=ffffffff-1111-2222-3333-444444444444","incidentWebUrl":"https://security.microsoft.com/incidents/INC-12345/overview?tid=ffffffff-1111-2222-3333-444444444444","actorDisplayName":null,"threatDisplayName":"Trojan:Win32/Example!pz","threatFamilyName":"Example","mitreTechniques":[],"createdDateTime":"2026-01-13T17:30:17.1666667Z","lastUpdateDateTime":"2026-01-13T17:30:54.2633333Z","resolvedDateTime":null,"firstActivityDateTime":"2026-01-13T17:18:53.041636Z","lastActivityDateTime":"2026-01-13T17:18:53.041636Z","systemTags":[],"alertPolicyId":null,"investigationState":"terminatedBySystem","comments":[],"customDetails":{},"evidence":[],"additionalData":{},"resource":"security","relationship":"alerts_v2"}}""",
            'json-msgraph',
            '99633',
            3,
            id='msgraph_resolved',
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


