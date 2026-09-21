#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log, send_multiple_logs

pytestmark = pytest.mark.wazuh_logtest


# Converted from iptables.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""Feb  4 23:33:37 hostname kernel: FIREWALL_OUT IN= OUT=eth0 SRC=192.168.6.57 DST=216.161.248.225 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=18547 DF PROTO=TCP SPT=46388 DPT=37628 WINDOW=6930 RES=0x00 ACK RST URGn=0""",
            'kernel',
            '4100',
            0,
            id='iptables_custom_action_1',
        ),
        pytest.param(
            r"""Feb  4 23:33:37 hostname kernel: IPTABLE IN=eth0 OUT= MAC=ff:ff:ff:ff:ff:ff:00:03:93:db:2e:b4:08:00 SRC=10.4.11.40 DST=255.255.255.255 LEN=180 TOS=0x00 PREC=0x00 TTL=64 ID=4753 PROTO=UDP SPT=49320 DPT=2222 LEN=160""",
            'kernel',
            '4100',
            0,
            id='iptables_custom_action_2',
        ),
        pytest.param(
            r"""Aug 17 10:03:37 myhostname kernel: SFW2-INext-DROP-DEFLT IN=eth0 OUT= MAC=00:08:02:da:c8:51:00:0f:f7:74:31:8a:08:00 SRC=1.2.3.36 DST=1.2.3.194 LEN=28 TOS=0x00 PREC=0x00 TTL=44 ID=60200 PROTO=ICMP TYPE=8 CODE=0 ID=10466 SEQ=21229""",
            'kernel',
            '4100',
            0,
            id='iptables_custom_action_3',
        ),
        pytest.param(
            r"""Aug 17 10:03:37 myhostname kernel: [4475569.016000] IN= OUT=lo SRC=192.168.2.11 DST=192.168.2.11 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=49546 DF PROTO=TCP SPT=43068 DPT=22 WINDOW=8192 RES=0x00 ACK URGP=0""",
            'kernel',
            '4100',
            0,
            id='iptables_custom_action_4',
        ),
        pytest.param(
            r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""",
            'kernel',
            '4101',
            5,
            id='iptables_drop',
        ),
        pytest.param(
            r"""Feb  4 23:33:37 hostname kernel: [ 3529.289825] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=254.253.252.251 DST=191.192.193.194 LEN=103 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=UDP SPT=53 DPT=36427 LEN=83""",
            'kernel',
            '4100',
            0,
            id='iptables_ufw_block_1',
        ),
        pytest.param(
            r"""Dec 26 09:05:47 server01 kernel: [126140.629122] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=254.253.252.251 DST=191.192.193.194 LEN=52 TOS=0x02 PREC=0x00 TTL=128 ID=9209 DF PROTO=TCP SPT=17833 DPT=22 WINDOW=8192 RES=0x00 CWR ECE SYN URGP=0""",
            'kernel',
            '4100',
            0,
            id='iptables_ufw_block_2',
        ),
        pytest.param(
            r"""Sep 20 15:52:00 managerHost kernel: [ 2870.303541] [UFW AUDIT] IN= OUT=ppp0 SRC=117.197.243.67 DST=218.248.255.163 LEN=62 TOS=0x00 PREC=0x00 TTL=64 ID=52751 DF PROTO=UDP SPT=57548 DPT=53 LEN=42""",
            'kernel',
            '4100',
            0,
            id='iptables_ufw_audit',
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
    ("logs", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            (r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0""", r"""Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0"""),
            'kernel',
            '4151',
            10,
            id='iptables_drop_frecuency',
        ),
        pytest.param(
            (r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00""", r"""Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00"""),
            'kernel',
            '4151',
            10,
            id='iptables_openwrt_drop_frecuency',
        ),
    ],
)
def test_rule_match_multiple_logs(
    logs: tuple[str, ...],
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    responses = send_multiple_logs(list(logs))
    response = responses[-1]

    assert response.status is LogtestStatus.RuleMatch
    assert response.decoder == decoder
    assert response.rule_id == rule_id
    assert response.rule_level == rule_level


