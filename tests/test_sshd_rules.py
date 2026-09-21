#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log, send_multiple_logs

pytestmark = pytest.mark.wazuh_logtest


# Converted from sshd.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""Feb  9 11:44:56 someserver sshd[1234]: error: Could not stat AuthorizedKeysCommand "/usr/local/sbin/ssh-ldap-authorized_keys": No such file or directory""",
            'sshd',
            '5739',
            4,
            id='sshd_configuration_error_authorizedkeyscommand',
        ),
        pytest.param(
            r"""Feb 10 23:21:05 someserver sshd[1234]: Read error from remote host 192.168.1.1: Connection reset by peer""",
            'sshd',
            '5740',
            4,
            id='ssh_connection_reset_by_peer',
        ),
        pytest.param(
            r"""Feb 11 06:41:50 someserver sshd[1234]: debug1: channel 5: connection failed: Connection refused""",
            'sshd',
            '5741',
            4,
            id='ssh_connection_refused',
        ),
        pytest.param(
            r"""Feb 12 17:45:09 someserver sshd[1234]: debug1: channel 3: connection failed: Connection timed out""",
            'sshd',
            '5742',
            4,
            id='ssh_connection_timed_out',
        ),
        pytest.param(
            r"""Jan 30 18:55:24 someserver sshd[1234]: debug1: channel 1: connection failed: No route to host""",
            'sshd',
            '5743',
            4,
            id='ssh_no_route_to_host',
        ),
        pytest.param(
            r"""Feb 13 22:54:51 someserver sshd[1234]: debug1: server_input_channel_open: failure direct-tcpip""",
            'sshd',
            '5744',
            4,
            id='ssh_port_forwarding_issue',
        ),
        pytest.param(
            r"""Feb  6 12:28:17 someserver sshd[1234]: debug1: getpeername failed: Transport endpoint is not connected""",
            'sshd',
            '5745',
            4,
            id='ssh_transport_endpoint_is_not_connected',
        ),
        pytest.param(
            r"""Feb  6 12:28:17 someserver sshd[1234]: debug1: get_remote_port failed""",
            'sshd',
            '5746',
            4,
            id='ssh_get_remote_port_failed',
        ),
        pytest.param(
            r"""Feb 14 14:34:15 someserver sshd[1234]: Corrupted MAC on input. [preauth]""",
            'sshd',
            '5748',
            6,
            id='ssh_corrupted_mac_on_input_1',
        ),
        pytest.param(
            r"""Nov 22 19:24:55 server sshd[4046]: Corrupted MAC on input.""",
            'sshd',
            '5748',
            6,
            id='ssh_corrupted_mac_on_input_2',
        ),
        pytest.param(
            r"""Mar  4 13:34:59 someserver sshd[5396]: Bad packet length 4081586742. [preauth]""",
            'sshd',
            '5749',
            4,
            id='ssh_bad_packet_length_1',
        ),
        pytest.param(
            r"""Mar  4 13:34:59 someserver sshd[5396]: Bad packet length 4081586742.""",
            'sshd',
            '5749',
            4,
            id='ssh_bad_packet_length_2',
        ),
        pytest.param(
            r"""Mar  3 10:56:18 junction sshd[32065]: fatal: Unable to negotiate with 202.191.177.33 port 3579: no matching cipher found. Their offer: 3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc [preauth]""",
            'sshd',
            '5753',
            2,
            id='ssh_unable_to_negotiate',
        ),
        pytest.param(
            r"""Sep 16 05:46:56 junction sshd[1961]: fatal: Unable to negotiate with 108.229.36.174: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1 [preauth]""",
            'sshd',
            '5752',
            2,
            id='ssh_no_matching_key_exchange_1',
        ),
        pytest.param(
            r"""Apr 18 21:27:08 web2 sshd[23484]: fatal: Unable to negotiate a key exchange method [preauth]""",
            'sshd',
            '5752',
            2,
            id='ssh_no_matching_key_exchange_2',
        ),
        pytest.param(
            r"""2013-10-30T14:51:21.901728+01:00 srv sshd[12664]: Postponed keyboard-interactive for invalid user warez from 192.241.237.101 port 54197 ssh2 [preauth]""",
            'sshd',
            '5710',
            5,
            id='invalid_user_1',
        ),
        pytest.param(
            r"""2013-10-30T14:51:30.267401+01:00 srv sshd[12671]: Invalid user opcione from 192.241.237.101""",
            'sshd',
            '5710',
            5,
            id='invalid_user_3',
        ),
        pytest.param(
            r"""2020-03-23 06:47:42.801612-0700  localhost sshd[3186]: error: PAM: unknown user for illegal user badguy from 192.168.33.1""",
            'sshd',
            '5710',
            5,
            id='invalid_user_5',
        ),
        pytest.param(
            r"""2020-03-25 08:01:34.584936-0700  localhost sshd[1551]: Failed keyboard-interactive/pam for invalid user user from 172.18.1.1 port 32982 ssh2""",
            'sshd',
            '5710',
            5,
            id='invalid_user_6',
        ),
        pytest.param(
            r"""2013-10-30T14:51:24.140565+01:00 srv sshd[12664]: Failed keyboard-interactive/pam for invalid user warez from 192.241.237.101 port 54197 ssh2""",
            'sshd',
            '5710',
            5,
            id='invalid_user_7',
        ),
        pytest.param(
            r"""2020-03-23 08:14:02.777660-0700  localhost sshd[8981]: error: PAM: authentication error for illegal user badguy from 192.168.33.1""",
            'sshd',
            '5710',
            5,
            id='invalid_user_8',
        ),
        pytest.param(
            r"""Jul  3 21:44:07 vmi189193 sshd[26279]: Failed password for invalid user sammy from 82.202.219.155 port 51676 ssh2""",
            'sshd',
            '5710',
            5,
            id='invalid_user_9',
        ),
        pytest.param(
            r"""May  4 17:48:43 collectd sshd[15044]: pam_systemd(sshd:session): Failed to create session: Access denied""",
            'sshd',
            '5754',
            1,
            id='failed_to_create_session',
        ),
        pytest.param(
            r"""May  4 18:30:04 collectd sshd[15191]: Authentication refused: bad ownership or modes for file /home/ansible/.ssh/authorized_keys""",
            'sshd',
            '5755',
            3,
            id='bad_authorized_keys',
        ),
        pytest.param(
            r"""May  5 05:00:38 junction sshd[28395]: subsystem request for netconf by user checker failed, subsystem not found""",
            'sshd',
            '5756',
            0,
            id='subsystem_failed',
        ),
        pytest.param(
            r"""Aug 18 07:30:25 192.168.1.5 sshd[20247]: [ID 800047 auth.notice] Failed none for root from 192.168.1.1 port 36942 ssh2""",
            'sshd',
            '5716',
            5,
            id='login_failed',
        ),
        pytest.param(
            r"""Oct 20 12:33:07 ar-agent sshd[3433]: Address 192.168.18.54 maps to nmap.18.168.192.in-addr.arpa, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!""",
            'sshd',
            '5757',
            0,
            id='bad_dns_1',
        ),
        pytest.param(
            r"""2020-03-25 09:01:30.852002-0700  localhost sshd[11885]: Address 192.168.33.1 maps to hostname, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!""",
            'sshd',
            '5757',
            0,
            id='bad_dns_2',
        ),
        pytest.param(
            r"""Dec 27 03:23:51 r1 sshd[21183]: error: maximum authentication attempts exceeded for root from 183.106.179.x port 34100 ssh2 [preauth]""",
            'sshd',
            '5758',
            8,
            id='max_auth_attempts_1',
        ),
        pytest.param(
            r"""2020-03-23 08:14:32.766049-0700  localhost sshd[8981]: error: maximum authentication attempts exceeded for invalid user badguy from 192.168.33.1 port 55146 ssh2 [preauth]""",
            'sshd',
            '5758',
            8,
            id='max_auth_attempts_2',
        ),
        pytest.param(
            r"""2020-03-23 09:58:27.102292-0700  localhost sshd[18093]: error: maximum authentication attempts exceeded for user from 192.168.33.1 port 55764 ssh2 [preauth]""",
            'sshd',
            '5758',
            8,
            id='max_auth_attempts_3',
        ),
        pytest.param(
            r"""2020-03-23 09:55:42.391078-0700  localhost sshd[17329]: error: PAM: authentication error for user from 192.168.33.1""",
            'sshd',
            '5760',
            5,
            id='sshd_authentication_error_1',
        ),
        pytest.param(
            r"""2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2""",
            'sshd',
            '5760',
            5,
            id='sshd_authentication_error_2',
        ),
        pytest.param(
            r"""2020-03-24 06:07:15.245255-0700  localhost sshd[195]: Connection closed by 10.0.2.2 port 55462 [preauth]""",
            'sshd',
            '5722',
            0,
            id='sshd_connection_close',
        ),
        pytest.param(
            r"""2020-03-24 08:38:47.230409-0700  localhost sshd[2531]: Disconnected from user user 172.18.1.100 port 43042""",
            'sshd',
            '5761',
            0,
            id='sshd_disconnected_from',
        ),
        pytest.param(
            r"""2020-03-24 08:38:47.230409-0700  localhost sshd[2531]: Disconnected from invalid user root 172.18.1.100 port 43042""",
            'sshd',
            '5710',
            5,
            id='sshd_disconnected_from_invalid',
        ),
        pytest.param(
            r"""2020-03-24 08:38:47.230409-0700  localhost sshd[2531]: Disconnecting invalid user root 172.18.1.100 port 43042""",
            'sshd',
            '5710',
            5,
            id='sshd_disconnecting_invalid',
        ),
        pytest.param(
            r"""2020-03-24 10:32:31.672920-0700  localhost sshd[5374]: Did not receive identification string from 172.18.1.1 port 45824""",
            'sshd',
            '5706',
            6,
            id='sshd_insecure_connection_attempt',
        ),
        pytest.param(
            r"""2020-03-25 08:23:20.933154-0700  localhost sshd[9265]: Connection reset by authenticating user user 192.168.33.1 port 51772 [preauth]""",
            'sshd',
            '5762',
            4,
            id='sshd_connection_reset',
        ),
        pytest.param(
            r"""2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers""",
            'sshd',
            '5718',
            5,
            id='sshd_denied_user_1',
        ),
        pytest.param(
            r"""2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers""",
            'sshd',
            '5718',
            5,
            id='sshd_denied_user_2',
        ),
        pytest.param(
            r"""2020-03-25 09:18:41.510217-0700  localhost sshd[2549]: reverse mapping checking getaddrinfo for hostname [172.18.1.1] failed - POSSIBLE BREAK.""",
            'sshd',
            '5702',
            5,
            id='sshd_reverse_lookup_error',
        ),
        pytest.param(
            r"""2020-03-25 06:37:50.176931-0700  localhost sshd[852]: Bad protocol version identification 'ls' from 172.18.1.1 port 59920""",
            'sshd',
            '5701',
            8,
            id='sshd_possible_attack',
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
            (r"""Feb  4 23:05:57 someserver sshd[1234]: Disconnecting: bad client public DH value [preauth]""", r"""Feb  4 23:05:57 someserver sshd[1234]: Disconnecting: bad client public DH value"""),
            'sshd',
            '5747',
            6,
            id='ssh_bad_client_public_dh_value',
        ),
        pytest.param(
            (r"""2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers""", r"""2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers""", r"""2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers""", r"""2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers""", r"""2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers""", r"""2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers""", r"""2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers""", r"""2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers"""),
            'sshd',
            '5719',
            10,
            id='sshd_multiple_access_attempts_using_a_denied_user',
        ),
        pytest.param(
            (r"""2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2""", r"""2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2""", r"""2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2""", r"""2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2""", r"""2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2""", r"""2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2""", r"""2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2""", r"""2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2"""),
            'sshd',
            '5763',
            10,
            id='sshd_brute_force_rule',
        ),
        pytest.param(
            (r"""May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233""", r"""May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233""", r"""May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233""", r"""May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233""", r"""May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233""", r"""May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233""", r"""May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233""", r"""May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233"""),
            'sshd',
            '5712',
            10,
            id='sshd_brute_force_rule_2',
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


@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""2013-10-30T14:51:24.139258+01:00 srv sshd[12664]: error: PAM: User not known to the underlying authentication module for illegal user warez from 192.241.237.101""",
            'sshd',
            '5710',
            5,
            id='invalid_user_2',
        ),
        pytest.param(
            r"""2013-10-30T14:51:30.267906+01:00 srv sshd[12671]: input_userauth_request: invalid user opcione [preauth]""",
            'sshd',
            '5710',
            5,
            id='invalid_user_4',
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


