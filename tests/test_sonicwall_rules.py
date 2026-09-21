#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from SonicWall.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r'''id=NSA3600  sn=C0EAE4599999 time="2019-02-27 12:55:40 UTC" fw=2.228.169.242 pri=5 c=0 m=1197 msg="NAT Mapping" n=4748427 src=10.12.14.9::X0-V500 dst=217.56.236.4::X3 proto=icmp note="Source: 2.228.169.242, 63130, Destination: 217.56.236.4, 8, Protocol: 1" rule="17 (LAN->WAN)"''',
            'sonicwall',
            '4805',
            0,
            id='sonicwall_acl_1',
        ),
        pytest.param(
            r"""id=firewall sn=C0EAE4599999 time="2019-02-15 09:45:17 UTC" fw=2.228.169.242 pri=5 c=512 m=1233 msg="Unhandled link-local or multicast IPv6 packet dropped" n=56642 srcV6=fe80::9851:b780:9d9d:a29e src=:49702:X0-V514 dstV6=ff02::1:3 dst=:5355 srcMac=90:e6:ba:32:5c:45 dstMac=33:33:00:01:00:03 proto=udp/5355""",
            'sonicwall',
            '4805',
            0,
            id='sonicwall_acl_2',
        ),
        pytest.param(
            r"""id=firewall sn=00301E0526B1 time="2004-04-01 10:39:35" fw=67.32.44.2 pri=5 c=64 m=36 msg="TCP connection dropped" n=2686 src=67.101.200.27:4507:WAN dst=67.32.44.2:445:LAN rule=0""",
            'sonicwall',
            '4805',
            0,
            id='sonicwall_acl_3',
        ),
        pytest.param(
            r'''id=NSA3600  sn=C0EAE4599999 time="2019-02-27 12:55:40 UTC" fw=2.228.169.242 pri=5 c=0 m=1197 msg="NAT Mapping" n=4748427 src=10.12.14.100::X0-V500 dst=217.56.236.200::X3 proto=icmp note="Source: 2.228.169.242, 63130, Destination: 217.56.236.200, 8, Protocol: 1" rule="17 (LAN->WAN)"''',
            'sonicwall',
            '4805',
            0,
            id='sonicwall_acl_4',
        ),
        pytest.param(
            r"""Jan  3 13:45:36 192.168.5.1 id=firewall sn=000SERIAL time="2007-01-03 14:48:06" fw=1.1.1.1 pri=6 c=262144 m=98 msg="Connection Opened" n=23419 src=2.2.2.2:36701:WAN dst=1.1.1.1:50000:WAN proto=tcp/50000""",
            'sonicwall',
            '4806',
            0,
            id='sonicwall_ac2_1',
        ),
        pytest.param(
            r"""Jan  3 13:45:36 192.168.5.1 id=firewall sn=000SERIAL time="2007-01-03 14:48:06" fw=1.1.1.1 pri=6 c=262144 m=98 msg="Connection Opened" n=23419 src=2.2.2.200:36701:WAN dst=1.1.1.100:50000:WAN proto=tcp/50000""",
            'sonicwall',
            '4806',
            0,
            id='sonicwall_ac2_2',
        ),
        pytest.param(
            r'''id=NSA3500BR sn=0017C5DFCEEC time="2019-03-14 16:37:19 UTC" fw=172.29.169.2 pri=1 c=32 m=1388 msg="IPSec VPN Decryption Failed" n=1064050271 src=37.186.204.2 dst=172.29.168.2 note="Replay check failure."''',
            'sonicwall',
            '4801',
            8,
            id='sonicwall_ac3_1',
        ),
        pytest.param(
            r"""Jan  3 13:45:36 192.168.5.1 id=firewall sn=000SERIAL time="2007-01-03 14:48:07" fw=1.1.1.1 pri=1 c=32 m=30 msg="Administrator login denied due to bad credentials" n=7 src=2.2.2.2:36701:WAN dst=1.1.1.1:50000:WAN""",
            'sonicwall',
            '4801',
            8,
            id='sonicwall_ac3_2',
        ),
        pytest.param(
            r'''id=NSA3500BR sn=0017C5DFCEEC time="2019-03-14 16:37:19 UTC" fw=172.29.169.2 pri=1 c=32 m=1388 msg="IPSec VPN Decryption Failed" n=1064050271 src=37.186.204.200 dst=172.29.168.100 note="Replay check failure."''',
            'sonicwall',
            '4801',
            8,
            id='sonicwall_ac3_3',
        ),
        pytest.param(
            r'''id=NSA2650GG sn=18B169D79980 time="2019-03-18 08:33:45 UTC" fw=83.211.91.146 pri=3 c=4 m=14 msg="Web site access denied" app=49177 appName="General HTTPS" n=838005 src=192.168.0.62:54993:X0:pc048.example.com dst=151.101.242.49:443:X1 srcMac=c8:9c:dc:fd:9d:02 dstMac=1a:b1:69:d7:99:80 proto=tcp/https dstname=example.com arg=/ code=49 Category="Freeware/Software Downloads"''',
            'sonicwall',
            '4803',
            4,
            id='sonicwall_ac4_1',
        ),
        pytest.param(
            r'''id=NSA2650GG sn=18B169D79980 time="2019-03-19 06:44:01 UTC" fw=83.211.91.146 pri=3 c=4 m=14 msg="Web site access denied" app=49177 appName="General HTTPS" n=856789 src=192.168.0.46:59668:X0:nb020.example.com dst=34.194.213.204:443:X1:example.com srcMac=a0:ce:c8:13:99:c5 dstMac=1a:b1:69:d7:99:80 proto=tcp/https dstname=example.com arg=/ code=49 Category="Freeware/Software Downloads"''',
            'sonicwall',
            '4803',
            4,
            id='sonicwall_ac4_2',
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


