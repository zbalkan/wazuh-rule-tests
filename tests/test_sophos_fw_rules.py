#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from sophos_fw.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70021',
            5,
            id='sophos_firewall_traffic_denied',
        ),
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Allowed" status="Allow" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70022',
            3,
            id='sophos_firewall_traffic_allowed',
        ),
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Detected" status="Detect" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70023',
            3,
            id='sophos_firewall_traffic_detect',
        ),
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Dropped" status="Drop" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70024',
            3,
            id='sophos_firewall_traffic_drop',
        ),
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Cleaned" status="Clean" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70025',
            3,
            id='sophos_firewall_traffic_clean',
        ),
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Virus" status="Virus" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70026',
            7,
            id='sophos_firewall_virus_detected',
        ),
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Spam" status="Spam" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70027',
            5,
            id='sophos_firewall_traffic_spam',
        ),
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Admin" status="Admin" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70028',
            3,
            id='sophos_firewall_traffic_admin',
        ),
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Authentication" status="Authentication" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70029',
            5,
            id='sophos_firewall_traffic_authentication',
        ),
        pytest.param(
            'device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="System" status="System" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat',
            'sophos-fw',
            '70030',
            3,
            id='sophos_firewall_traffic_system',
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


