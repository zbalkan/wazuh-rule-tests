#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from cisco_ftd.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '%FTD-1-101001: (Primary) Failover cable OK.',
            'cisco-ftd',
            '91501',
            7,
            id='cisco_ftd_high_severity_alert_1',
        ),
        pytest.param(
            '%FTD-1-101002: (Primary) Bad failover cable.',
            'cisco-ftd',
            '91501',
            7,
            id='cisco_ftd_high_severity_alert_2',
        ),
        pytest.param(
            '%FTD-2-106001: Inbound TCP connection denied from 192.168.1.59/port to 192.168.1.59/port flags tcp_flags on interface interface_name',
            'cisco-ftd',
            '91502',
            5,
            id='cisco_ftd_critical_severity_alert_1',
        ),
        pytest.param(
            '%FTD-2-106002: protocol Connection denied by outbound list acl_ID src inside_address dest outside_address',
            'cisco-ftd',
            '91502',
            5,
            id='cisco_ftd_critical_severity_alert_2',
        ),
        pytest.param(
            '%FTD-3-106010: Deny inbound protocol src [interface_name: 192.168.1.59/source_port] [([idfw_user | FQDN_string], sg_info)] dst [interface_name: 192.168.1.59/dest_port}[([idfw_user | FQDN_string], sg_info)]',
            'cisco-ftd',
            '91503',
            4,
            id='cisco_ftd_error_alert_1',
        ),
        pytest.param(
            '%FTD-3-106011: Deny inbound (No xlate) string',
            'cisco-ftd',
            '91503',
            4,
            id='cisco_ftd_error_alert_2',
        ),
        pytest.param(
            '%FTD-4-106023: Deny tcp src inside:111.11.11.1/2143 dst YYY:172.11.1.11/139 by access-group "inside_inbound"',
            'cisco-ftd',
            '91504',
            3,
            id='cisco_ftd_warning_alert_1',
        ),
        pytest.param(
            '%FTD-4-106027: Deny src [source address] dst [destination address] by access-group "access-list name".',
            'cisco-ftd',
            '91504',
            3,
            id='cisco_ftd_warning_alert_2',
        ),
        pytest.param(
            '%FTD-5-106029: New reverse carrier <protocol> <ingress_ifc>:<source_addr> to <egress_ifc>:<destination_addr> overshadows existing <ingress_ifc2>:<source_addr2> to <egress_ifc2>:<destination_addr2>',
            'cisco-ftd',
            '91505',
            2,
            id='cisco_ftd_notification_alerts_1',
        ),
        pytest.param(
            "%FTD-5-109012: Authen Session End: user 'user', sid number, elapsed number seconds",
            'cisco-ftd',
            '91505',
            2,
            id='cisco_ftd_notification_alerts_2',
        ),
        pytest.param(
            '%FTD-6-106015: Deny TCP (no connection) from 192.168.1.59/port to 192.168.1.59/port flags tcp_flags on interface interface_name.',
            'cisco-ftd',
            '91505',
            2,
            id='cisco_ftd_notification_alerts_3',
        ),
        pytest.param(
            '%FTD-6-106100: access-list acl_ID {permitted | denied | est-allowed} protocol interface_name/192.168.1.59(source_port)(idfw_user, sg_info) interface_name/192.168.1.59(dest_port) (idfw_user, sg_info) hit-cnt number ({first hit | number-second interval})',
            'cisco-ftd',
            '91505',
            2,
            id='cisco_ftd_notification_alerts_4',
        ),
        pytest.param(
            '%FTD-7-113028: Extraction of username from VPN client certificate has string. [Request num]',
            'cisco-ftd',
            '91506',
            0,
            id='cisco_ftd_debugging_alerts_1',
        ),
        pytest.param(
            '%FTD-7-199019: syslog',
            'cisco-ftd',
            '91506',
            0,
            id='cisco_ftd_debugging_alerts_2',
        ),
        pytest.param(
            '%FTD-6-605004: Login denied from source-address/source-port to interface:destination/service for user "username"',
            'cisco-ftd',
            '91507',
            9,
            id='cisco_ftd_failed_login_attempt',
        ),
        pytest.param(
            '%FTD-5-502103: User priv level changed: Uname: user From: privilege_level To: privilege_level',
            'cisco-ftd',
            '91508',
            3,
            id='cisco_ftd_user_privilege_changed',
        ),
        pytest.param(
            '%FTD-6-605005: Login permitted from source-address/source-port to interface:destination/service for user "username"',
            'cisco-ftd',
            '91509',
            3,
            id='cisco_ftd_successful_login',
        ),
        pytest.param(
            '%FTD-4-405001: Received ARP {request | response} collision from 192.168.1.59/MAC_address on interface interface_name to 192.168.1.59/MAC_address on interface interface_name',
            'cisco-ftd',
            '91510',
            8,
            id='cisco_ftd_arp_collision_detected',
        ),
        pytest.param(
            '%FTD-4-401004: Shunned packet: 192.168.1.59 = 192.168.1.59 on interface interface_name',
            'cisco-ftd',
            '91511',
            8,
            id='cisco_ftd_attempt_to_connect_from_a_blocked_ip',
        ),
        pytest.param(
            '%FTD-7-710004: TCP connection limit exceeded from Src_ip/Src_port to In_name:Dest_ip/Dest_port (current connections/connection limit = Curr_conn/Conn_lmt)',
            'cisco-ftd',
            '91512',
            8,
            id='cisco_ftd_connection_limit_exceeded',
        ),
        pytest.param(
            '%FTD-6-106012: Deny IP from 192.168.1.59 to 192.168.1.59, IP options hex.',
            'cisco-ftd',
            '91515',
            8,
            id='cisco_ftd_attack_in_progress_detected_1',
        ),
        pytest.param(
            '%FTD-1-106022: Deny protocol connection spoof from 192.168.1.59 to 192.168.1.59 on interface interface_name',
            'cisco-ftd',
            '91515',
            8,
            id='cisco_ftd_attack_in_progress_detected_2',
        ),
        pytest.param(
            '%FTD-1-106021: Deny protocol reverse path check from 192.168.1.59 to 192.168.1.59 on interface interface_name',
            'cisco-ftd',
            '91515',
            8,
            id='cisco_ftd_attack_in_progress_detected_3',
        ),
        pytest.param(
            '%FTD-2-106017: Deny IP due to Land Attack from 192.168.1.59 to 192.168.1.59',
            'cisco-ftd',
            '91515',
            8,
            id='cisco_ftd_attack_in_progress_detected_4',
        ),
        pytest.param(
            '%FTD-2-106020: Deny IP teardrop fragment (size = number, offset = number) from 192.168.1.59 to 192.168.1.59',
            'cisco-ftd',
            '91515',
            8,
            id='cisco_ftd_attack_in_progress_detected_5',
        ),
        pytest.param(
            '%FTD-6-113005: AAA user authentication Rejected: reason = string: server = server_192.168.1.59, User = user: user IP = user_ip',
            'cisco-ftd',
            '91516',
            5,
            id='cisco_ftd_aaa_vpn_authentication_failed',
        ),
        pytest.param(
            '%FTD-6-113004: AAA user aaa_type Successful: server = server_192.168.1.59, User = user',
            'cisco-ftd',
            '91517',
            3,
            id='cisco_ftd_aaa_vpn_authentication_successful',
        ),
        pytest.param(
            '%FTD-6-113006: User user locked out on exceeding number successive failed authentication attempts',
            'cisco-ftd',
            '91518',
            8,
            id='cisco_ftd_aaa_vpn_user_locked_out',
        ),
        pytest.param(
            '%FTD-3-201008: Disallowing new connections.',
            'cisco-ftd',
            '91519',
            8,
            id='cisco_ftd_disallowing_new_connections',
        ),
        pytest.param(
            '%FTD-1-105005: (Primary) Lost Failover communications with mate on interface interface_name.',
            'cisco-ftd',
            '91520',
            8,
            id='cisco_ftd_firewall_failover_pair_communication_problem_1',
        ),
        pytest.param(
            '%FTD-1-105009: (Primary) Testing on interface interface_name {Passed|Failed}.',
            'cisco-ftd',
            '91520',
            8,
            id='cisco_ftd_firewall_failover_pair_communication_problem_2',
        ),
        pytest.param(
            '%FTD-1-105043: (Primary) Failover interface failed',
            'cisco-ftd',
            '91520',
            8,
            id='cisco_ftd_firewall_failover_pair_communication_problem_3',
        ),
        pytest.param(
            '%FTD-5-111003: 192.168.1.59 Erase configuration',
            'cisco-ftd',
            '91521',
            8,
            id='cisco_ftd_firewall_configuration_deleted',
        ),
        pytest.param(
            '%FTD-5-111002: Begin configuration: 192.168.1.59 reading from device',
            'cisco-ftd',
            '91522',
            8,
            id='cisco_ftd_firewall_configuration_changed_1',
        ),
        pytest.param(
            '%FTD-5-111004: 192.168.1.59 end configuration: {FAILED|OK}',
            'cisco-ftd',
            '91522',
            8,
            id='cisco_ftd_firewall_configuration_changed_2',
        ),
        pytest.param(
            '%FTD-5-111005: 192.168.1.59 end configuration: OK',
            'cisco-ftd',
            '91522',
            8,
            id='cisco_ftd_firewall_configuration_changed_3',
        ),
        pytest.param(
            '%FTD-5-111007: Begin configuration: 192.168.1.59 reading from device.',
            'cisco-ftd',
            '91522',
            8,
            id='cisco_ftd_firewall_configuration_changed_4',
        ),
        pytest.param(
            '%FTD-5-111008: User user executed the command string',
            'cisco-ftd',
            '91523',
            3,
            id='cisco_ftd_firewall_command_executed_for_accounting_only',
        ),
        pytest.param(
            '%FTD-7-111009: User user executed cmd:string',
            'cisco-ftd',
            '91524',
            3,
            id='cisco_ftd_firewall_command_executed_for_accounting',
        ),
        pytest.param(
            '%FTD-5-502101: New user added to local dbase: Uname: user Priv: privilege_level Encpass: string',
            'cisco-ftd',
            '91525',
            8,
            id='cisco_ftd_user_created_or_modified_on_the_firewall_1',
        ),
        pytest.param(
            '%FTD-5-502102: User deleted from local dbase: Uname: user Priv: privilege_level Encpass: string',
            'cisco-ftd',
            '91525',
            8,
            id='cisco_ftd_user_created_or_modified_on_the_firewall_2',
        ),
        pytest.param(
            '%FTD-2-106016: Deny IP spoof from (192.168.1.59) to 192.168.1.59 on interface interface_name.',
            'cisco-ftd',
            '91530',
            8,
            id='cisco_ftd_ip_spoofing_attack_detected',
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


