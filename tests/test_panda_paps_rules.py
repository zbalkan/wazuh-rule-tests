#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from panda_paps.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=1\tdevTime=2019-05-09 22:03:58.692466\tdevTimeFormat=yyyy-MM-dd HH:mm:ss.SSS\tusrName=SYSTEM\tdomain=NT AUTHORITY\tsrc=192.168.0.8\tidentSrc=192.168.0.8\tidentHostName=13_2595_43\tHostName=13_2595_43\tMUID=6C6A0D57714FE5B6D72BA0EC0E46D71B\tOp=ModifyExeKey\tHash=E60A27AAEB184AABD9C92C513B27F98A\tDriveType=Fixed\tPath=PROGRAM_FILES_COMMONX86|\\Quest\\Privilege Manager\\Client\\CSEHost.exe\tValidSig=true\tCompany=Quest Software Inc.\tBroken=false\tImageType=EXE 32\tExeType=Unknown\tPrevalence=Medium\tPrevLastDay=Low\tCat=Goodware\tMWName=\tTargetPath=3|PROGRAM_FILES_COMMONX86|\\Quest\\Privilege Manager\\Client\\GPEEventMsgFile.dll\tRegKey=\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\services\\eventlog\\Application\\GPE Alert?EventMessageFile',
            'paps',
            '64201',
            7,
            id='panda_paps_alert_message_received',
        ),
        pytest.param(
            'LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=3\tdevTime=2019-05-09 22:01:23.255825\tdevTimeFormat=yyyy-MM-dd HH:mm:ss.SSS\tusrName=SYSTEM\tdomain=NT AUTHORITY\tsrc=10.255.44.11\tidentSrc=10.255.44.11\tidentHostName=44_CCO_11\tHostName=44_CCO_11\tMUID=D877F2C4C4000A9BF39F1710CA787291\tOp=ModifyExeKey\tHash=F6494E7C35B6514A3AD74E27435F3141\tDriveType=Fixed\tPath=PROGRAM_FILESX86|\\LANDesk\\LDClient\\hips\\LDSecSvc64.EXE\tValidSig=true\tCompany=LANDESK Software, Inc. and its affiliates.\tBroken=false\tImageType=EXE 64\tExeType=Unknown\tPrevalence=Low\tPrevLastDay=Low\tCat=Goodware\tMWName=\tTargetPath=3|PROGRAM_FILESX86|\\LANDesk\\LDClient\\LDdrives.exe',
            'paps',
            '64202',
            4,
            id='panda_paps_low_severity_event_detected',
        ),
        pytest.param(
            'LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=5\tdevTime=2019-05-09 22:01:23.255825\tdevTimeFormat=yyyy-MM-dd HH:mm:ss.SSS\tusrName=SYSTEM\tdomain=NT AUTHORITY\tsrc=10.255.44.11\tidentSrc=10.255.44.11\tidentHostName=44_CCO_11\tHostName=44_CCO_11\tMUID=D877F2C4C4000A9BF39F1710CA787291\tOp=ModifyExeKey\tHash=F6494E7C35B6514A3AD74E27435F3141\tDriveType=Fixed\tPath=PROGRAM_FILESX86|\\LANDesk\\LDClient\\hips\\LDSecSvc64.EXE\tValidSig=true\tCompany=LANDESK Software, Inc. and its affiliates.\tBroken=false\tImageType=EXE 64\tExeType=Unknown\tPrevalence=Low\tPrevLastDay=Low\tCat=Goodware\tMWName=\tTargetPath=3|PROGRAM_FILESX86|\\LANDesk\\LDClient\\LDdrives.exe',
            'paps',
            '64203',
            4,
            id='panda_paps_medium_severity_event_detected',
        ),
        pytest.param(
            'LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=7\tdevTime=2019-05-09 22:01:23.255825\tdevTimeFormat=yyyy-MM-dd HH:mm:ss.SSS\tusrName=SYSTEM\tdomain=NT AUTHORITY\tsrc=10.255.44.11\tidentSrc=10.255.44.11\tidentHostName=44_CCO_11\tHostName=44_CCO_11\tMUID=D877F2C4C4000A9BF39F1710CA787291\tOp=ModifyExeKey\tHash=F6494E7C35B6514A3AD74E27435F3141\tDriveType=Fixed\tPath=PROGRAM_FILESX86|\\LANDesk\\LDClient\\hips\\LDSecSvc64.EXE\tValidSig=true\tCompany=LANDESK Software, Inc. and its affiliates.\tBroken=true\tImageType=EXE 64\tExeType=Unknown\tPrevalence=Low\tPrevLastDay=Low\tCat=Goodware\tMWName=\tTargetPath=3|PROGRAM_FILESX86|\\LANDesk\\LDClient\\LDdrives.exe',
            'paps',
            '64204',
            12,
            id='panda_paps_high_severity_event_detected',
        ),
        pytest.param(
            'LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=9\tdevTime=2019-05-09 22:01:23.255825\tdevTimeFormat=yyyy-MM-dd HH:mm:ss.SSS\tusrName=SYSTEM\tdomain=NT AUTHORITY\tsrc=10.255.44.11\tidentSrc=10.255.44.11\tidentHostName=44_CCO_11\tHostName=44_CCO_11\tMUID=D877F2C4C4000A9BF39F1710CA787291\tOp=ModifyExeKey\tHash=F6494E7C35B6514A3AD74E27435F3141\tDriveType=Fixed\tPath=PROGRAM_FILESX86|\\LANDesk\\LDClient\\hips\\LDSecSvc64.EXE\tValidSig=true\tCompany=LANDESK Software, Inc. and its affiliates.\tBroken=true\tImageType=EXE 64\tExeType=Unknown\tPrevalence=Low\tPrevLastDay=Low\tCat=Goodware\tMWName=\tTargetPath=3|PROGRAM_FILESX86|\\LANDesk\\LDClient\\LDdrives.exe',
            'paps',
            '64205',
            14,
            id='panda_paps_very_high_severity_event_detected',
        ),
        pytest.param(
            'LEEF:1.0|Panda Security|paps|02.47.00.0000|exec|sev=1\tdevTime=2019-05-09 22:07:36.130735\tdevTimeFormat=yyyy-MM-dd HH:mm:ss.SSS\tusrName=hsmartin\tdomain=PROSAMX\tsrc=10.255.16.21\tidentSrc=10.255.16.21\tidentHostName=16_2470_21\tHostName=16_2470_21\tMUID=577C98BB9DC2523C1AEDE584FCAF1615\tOp=Exec\tParentHash=7E160844D950765356C84BCBCFBF1DEE\tParentDriveType=Fixed\tParentPath=PROGRAM_FILESX86|\\Google\\Chrome\\Application\\chrome.exe\tParentValidSig=true\tParentCompany=Google Inc.\tParentBroken=false\tParentImageType=EXE 64\tParentExeType=Unknown\tParentPrevalence=High\tParentPrevLastDay=Low\tParentCat=Goodware\tParentMWName=\tChildHash=7E160844D950765356C84BCBCFBF1DEE\tChildDriveType=Fixed\tChildPath=PROGRAM_FILESX86|\\Google\\Chrome\\Application\\chrome.exe\tChildValidSig=true\tChildCompany=Google Inc.\tChildBroken=true\tChildImageType=EXE 64\tChildExeType=Unknown\tChildPrevalence=High\tChildPrevLastDay=Low\tChildCat=Goodware\tChildMWName=\tOCS_Exec=true\tOCS_Name=Google Chrome\tOCS_Version=71.0.3578.80\tParams="C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe" --type\\=renderer --field-trial-handle\\=1716,6504423765877186287,9579056321151338165,131072 --service-pipe-token\\=11343697476573359606 --lang\\=es --extension-process --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor\\=1 --num-raster-threads\\=4 --enable-main-frame-before-activation --service-request-channel-token\\=11343697476573359606 --renderer-client-id\\=629 --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle\\=17588 /prefetch:1\tToastResult=\tAction=Allow\tServiceLevel=Learning\tWinningTech=Cloud\tDetId=0',
            'paps',
            '64206',
            7,
            id='panda_paps_the_child_process_is_corrupted_or_defective',
        ),
        pytest.param(
            'LEEF:1.0|Panda Security|paps|02.47.00.0000|createdir|sev=1\tdevTime=2019-05-09 21:59:51.410364\tdevTimeFormat=yyyy-MM-dd HH:mm:ss.SSS\tusrName=SYSTEM\tdomain=NT AUTHORITY\tsrc=10.255.16.21\tidentSrc=10.255.16.21\tidentHostName=16_2470_21\tHostName=16_2470_21\tMUID=577C98BB9DC2523C1AEDE584FCAF1615\tOp=CreateDir\tParentHash=C05A19A38D7D203B738771FD1854656F\tParentDriveType=Fixed\tParentPath=SYSTEM|\\spoolsv.exe\tParentValidSig=\tParentCompany=Microsoft Corporation\tParentBroken=true\tParentImageType=EXE 64\tParentExeType=Unknown\tParentPrevalence=High\tParentPrevLastDay=Low\tParentCat=Goodware\tParentMWName=\tChildHash=\tChildDriveType=Fixed\tChildPath=SYSTEM|\\spool\\V4Dirs\\5F1D9A23-55FC-420A-84EC-E78F46C362E2\tChildValidSig=\tChildCompany=\tChildBroken=\tChildImageType=\tChildExeType=\tChildPrevalence=\tChildPrevLastDay=\tChildCat=Unknown\tChildMWName=\tOCS_Exec=false\tOCS_Name=\tOCS_Version=\tParams=\tToastResult=\tAction=Allow\tServiceLevel=Learning\tWinningTech=Unknown\tDetId=0',
            'paps',
            '64207',
            7,
            id='panda_paps_the_parent_process_is_corrupted_or_defective',
        ),
        pytest.param(
            'LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=1\tdevTime=2019-05-09 22:01:23.255825\tdevTimeFormat=yyyy-MM-dd HH:mm:ss.SSS\tusrName=SYSTEM\tdomain=NT AUTHORITY\tsrc=10.255.44.11\tidentSrc=10.255.44.11\tidentHostName=44_CCO_11\tHostName=44_CCO_11\tMUID=D877F2C4C4000A9BF39F1710CA787291\tOp=ModifyExeKey\tHash=F6494E7C35B6514A3AD74E27435F3141\tDriveType=Fixed\tPath=PROGRAM_FILESX86|\\LANDesk\\LDClient\\hips\\LDSecSvc64.EXE\tValidSig=true\tCompany=LANDESK Software, Inc. and its affiliates.\tBroken=true\tImageType=EXE 64\tExeType=Unknown\tPrevalence=Low\tPrevLastDay=Low\tCat=Goodware\tMWName=\tTargetPath=3|PROGRAM_FILESX86|\\LANDesk\\LDClient\\LDdrives.exe',
            'paps',
            '64208',
            7,
            id='panda_paps_a_file_is_corrupted_or_defective',
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


