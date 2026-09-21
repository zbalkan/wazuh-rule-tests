#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from dovecot.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""Dec 19 06:21:06 ny dovecot: imap-login: Disconnected (auth failed, 7 attempts in 111 secs): user=<thousands>, method=PLAIN, rip=109.201.200.201, lip=67.205.141.203, session=<+hgd5vxDBMZtycjJ>""",
            'dovecot',
            '9705',
            5,
            id='auth_failed_1',
        ),
        pytest.param(
            r"""Jan 11 03:45:09 hostname dovecot: auth-worker(default): sql(username,1.2.3.4): unknown user""",
            'dovecot',
            '9705',
            5,
            id='auth_failed_2',
        ),
        pytest.param(
            r"""Jan 11 03:42:09 hostname dovecot: auth(default): pam(user@example.com,1.2.3.4): pam_authenticate() failed: User not known to the underlying authentication module""",
            'dovecot',
            '9705',
            5,
            id='auth_failed_3',
        ),
        pytest.param(
            r"""Jun 17 10:15:24 hostname dovecot: Dovecot v1.2.rc3 starting up (core dumps disabled)""",
            'dovecot',
            '9703',
            3,
            id='dovecot_is_starting',
        ),
        pytest.param(
            r"""Jun 17 10:15:24 hostname dovecot: Fatal: auth(default): Support not compiled in for passdb driver 'ldap'""",
            'dovecot',
            '9704',
            2,
            id='fatal_error_1',
        ),
        pytest.param(
            r"""Jun 17 10:15:24 hostname dovecot: Fatal: Auth process died too early - shutting down""",
            'dovecot',
            '9704',
            2,
            id='fatal_error_2',
        ),
        pytest.param(
            r"""Jun 23 15:04:05 Info: imap-login: Login: user=<username>, method=PLAIN, rip=1.2.3.4, lip=1.2.3.5 Authentication Failure:""",
            'dovecot-info',
            '9770',
            0,
            id='user_authentication_failure',
        ),
        pytest.param(
            r"""Jan 11 03:42:09 hostname dovecot: auth-worker(default): sql(user@example.com,1.2.3.4): Password mismatch""",
            'dovecot',
            '9702',
            5,
            id='dovecot_auth_failed',
        ),
        pytest.param(
            r"""Mar 13 15:25:07 Info: auth(default): pam(user@example.com,::ffff:1.2.3.4): pam_authenticate() failed: User not known to the underlying authentication module""",
            'dovecot-info',
            '9771',
            5,
            id='xxx_unknown_1002',
        ),
        pytest.param(
            r"""Jul  4 17:30:51 hostname dovecot[2992]: pop3-login: Disconnected: rip=1.2.3.4, lip=1.2.3.5""",
            'dovecot',
            '9706',
            3,
            id='session_disconnected',
        ),
        pytest.param(
            r"""Jan 30 09:37:55 hostname dovecot: pop3-login: Aborted login: user=<username>, method=PLAIN, rip=::ffff:1.2.3.4, lip=::ffff:1.2.3.5""",
            'dovecot',
            '9707',
            5,
            id='aborted_login',
        ),
        pytest.param(
            r"""Mar 13 15:25:07 Info: auth(default): passwd-file(user@example.com,::ffff:1.2.3.4): unknown user""",
            'dovecot-info',
            '9771',
            5,
            id='unknown_user',
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
            r"""Jan 07 14:46:28 Warn: auth(default): userdb(username,::ffff:127.0.0.1): user not found from userdb""",
            '',
            '1002',
            2,
            id='xxx_nothing_1',
        ),
        pytest.param(
            r"""May 31 09:43:57 Info: pop3-login: Aborted login (1 authentication attempts): user=<username>, method=PLAIN, rip=::ffff:1.2.3.4, lip=::ffff:1.2.3.5, secured""",
            '',
            '1002',
            2,
            id='xxx_nothing_2',
        ),
        pytest.param(
            r"""Jun 23 15:04:06 Info: IMAP(username): Disconnected: Logged out bytes=59/566""",
            'dovecot-info',
            '1002',
            2,
            id='xxx_logged_out',
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


