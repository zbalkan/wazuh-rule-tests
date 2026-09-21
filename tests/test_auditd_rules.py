#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log, send_multiple_logs

pytestmark = pytest.mark.wazuh_logtest


# Converted from auditd.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""type=DAEMON_RESUME msg=audit(1300385209.456:8846): auditd resuming logging, sending auid=? pid=? subj=? res=success""",
            'auditd',
            '80701',
            1,
            id='auditd_daemon_start_resume',
        ),
        pytest.param(
            r"""type=DAEMON_START msg=audit(1450875964.131:8728): auditd start, ver=2.4 format=raw kernel=3.16.0-4-amd64 auid=4294967295 pid=1437 res=failed""",
            'auditd',
            '80702',
            10,
            id='auditd_daemon_start_resume_failed',
        ),
        pytest.param(
            r"""type=DAEMON_END msg=audit(1450876093.165:8729): auditd normal halt, sending auid=0 pid=1 subj= res=success""",
            'auditd',
            '80703',
            10,
            id='auditd_daemon_end',
        ),
        pytest.param(
            r"""type=DAEMON_ABORT msg=audit(1339336882.189:9206): auditd error halt, auid=4294967295 pid=3095 res=failed""",
            'auditd',
            '80704',
            10,
            id='auditd_daemon_abort',
        ),
        pytest.param(
            r"""type=ANOM_PROMISCUOUS msg=audit(1390181243.575:738): dev=vethDvSeyL prom=256 old_prom=256 auid=4294967295 uid=0 gid=0 ses=4294967295""",
            'auditd',
            '80710',
            10,
            id='auditd_device_enables_promiscuous_mode',
        ),
        pytest.param(
            r"""type=ANOM_ABEND msg=audit(1222174623.498:608): auid=4294967295 uid=0 gid=7 ses=4294967295 subj=system_u:system_r:cupsd_t:s0-s0:c0.c1023 pid=7192 comm="ipp" sig=11""",
            'auditd',
            '80711',
            10,
            id='auditd_process_ended_abnormally',
        ),
        pytest.param(
            r"""type=ANOM_EXEC msg=audit(1222174623.498:608): user pid=12965 uid=1 auid=2 ses=1 msg='op=PAM:unix_chkpwd acct="snap" exe="/sbin/unix_chkpwd" (hostname=?, addr=?, terminal=pts/0 res=failed)'""",
            'auditd',
            '80712',
            10,
            id='auditd_execution_of_a_file_ended_abnormally',
        ),
        pytest.param(
            r"""type=ANOM_MK_EXEC msg=audit(1234567890.123:1234): Text""",
            'auditd',
            '80713',
            7,
            id='auditd_file_is_made_executable',
        ),
        pytest.param(
            r"""type=ANOM_ACCESS_FS msg=audit(1234567890.123:1234): Text""",
            'auditd',
            '80714',
            8,
            id='auditd_file_or_a_directory_access_ended_abnormally',
        ),
        pytest.param(
            r"""type=ANOM_AMTU_FAIL msg=audit(1234567890.123:1234): Text""",
            'auditd',
            '80715',
            8,
            id='auditd_failure_of_the_abstract_machine_test_utility_amtu_detected',
        ),
        pytest.param(
            r"""type=ANOM_MAX_DAC msg=audit(1234567890.123:1234): Text""",
            'auditd',
            '80716',
            8,
            id='auditd_maximum_amount_of_discretionary_access_control_dac_or_mandatory_access_control_mac_failures_reached',
        ),
        pytest.param(
            r"""type=ANOM_ADD_ACCT msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80718',
            3,
            id='auditd_user_space_account_addition_ended_abnormally',
        ),
        pytest.param(
            r"""type=ANOM_DEL_ACCT msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80719',
            3,
            id='auditd_user_space_account_deletion_ended_abnormally',
        ),
        pytest.param(
            r"""type=ANOM_MOD_ACCT msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80720',
            3,
            id='auditd_user_space_account_modification_ended_abnormally',
        ),
        pytest.param(
            r"""type=ANOM_ROOT_TRANS msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80721',
            10,
            id='auditd_user_becomes_root',
        ),
        pytest.param(
            r"""type=ANOM_LOGIN_ACCT msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80722',
            5,
            id='auditd_account_login_attempt_ended_abnormally',
        ),
        pytest.param(
            r"""type=ANOM_LOGIN_FAILURES msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80723',
            5,
            id='auditd_limit_of_failed_login_attempts_reached',
        ),
        pytest.param(
            r"""type=ANOM_LOGIN_LOCATION msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80724',
            5,
            id='auditd_login_attempt_from_a_forbidden_location',
        ),
        pytest.param(
            r"""type=ANOM_LOGIN_SESSIONS msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80725',
            4,
            id='auditd_login_attempt_reached_the_maximum_amount_of_concurrent_sessions',
        ),
        pytest.param(
            r"""type=ANOM_LOGIN_TIME msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80726',
            5,
            id='auditd_login_attempt_is_made_at_a_time_when_it_is_prevented',
        ),
        pytest.param(
            r"""type=AVC msg=audit(1226270358.848:238): avc:  denied  { write } for  pid=13349 comm="certwatch" name="cache" dev=dm-0 ino=218171 scontext=system_u:system_r:certwatch_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=dir""",
            'auditd',
            '80730',
            3,
            id='auditd_selinux_permission_check',
        ),
        pytest.param(
            r"""type=MAC_STATUS msg=audit(1336836093.835:406): enforcing=1 old_enforcing=0 auid=0 ses=2""",
            'auditd',
            '80731',
            10,
            id='auditd_selinux_mode_enforcing_permissive_off_is_changed',
        ),
        pytest.param(
            r"""type=CRYPTO_REPLAY_USER msg=audit(1234567890.123:1234): Text""",
            'auditd',
            '80740',
            12,
            id='auditd_replay_attack_detected',
        ),
        pytest.param(
            r"""type=CHGRP_ID msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80741',
            5,
            id='auditd_group_id_changed',
        ),
        pytest.param(
            r"""type=CHUSER_ID msg=audit(1450770603.209:3300446): Text""",
            'auditd',
            '80742',
            5,
            id='auditd_user_id_changed',
        ),
        pytest.param(
            r"""type=ACCT_LOCK msg=audit(1630937849.448:891): pid=4171 uid=0 auid=1000 ses=3 subj=unconfined_u:unconfined_r:passwd_t:s0-s0:c0.c1023 msg='op=locked-password id=1001 exe="/usr/bin/passwd" hos>""",
            'auditd',
            '80793',
            8,
            id='audit_passwd_was_used_to_lock_an_account',
        ),
        pytest.param(
            r"""type=ACCT_UNLOCK msg=audit(1630937871.591:892): pid=4172 uid=0 auid=1000 ses=3 subj=unconfined_u:unconfined_r:passwd_t:s0-s0:c0.c1023 msg='op=unlocked-password id=1001 exe="/usr/bin/passwd">""",
            'auditd',
            '80794',
            8,
            id='audit_passwd_was_used_to_unlock_an_account',
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
            (r"""type=CONFIG_CHANGE msg=audit(1368831799.081:466947): auid=4294967295 ses=4294967295 op="remove rule" path="/path/to/my/bin0" key=(null) list=4 res=1""", r"""type=DAEMON_CONFIG msg=audit(1264985324.554:4915): auditd error getting hup info - no change, sending auid=? pid=? subj=? res=failed"""),
            'auditd',
            '80705',
            3,
            id='auditd_configuration_changed',
        ),
        pytest.param(
            (r"""type=ANOM_AMTU_FAIL msg=audit(1234567890.123:1234): Text""", r"""type=ANOM_RBAC_INTEGRITY_FAIL msg=audit(1234567890.123:1234): Text"""),
            'auditd',
            '80717',
            8,
            id='auditd_role_based_access_control_rbac_failure_detected',
        ),
        pytest.param(
            (r"""type=SELINUX_ERR msg=audit(1311948547.151:138): op=security_compute_av reason=bounds scontext=system_u:system_r:anon_webapp_t:s0-s0:c0,c100,c200 tcontext=system_u:object_r:security_t:s0 tclass=dir perms=ioctl,read,lock""", r"""type=USER_SELINUX_ERR msg=audit(1311948547.151:138): Text"""),
            'auditd',
            '80732',
            10,
            id='auditd_selinux_error',
        ),
        pytest.param(
            (r"""type=SYSCALL msg=audit(1479982525.380:50): arch=c000003e syscall=2 success=yes exit=3 a0=7ffedc40d83b a1=941 a2=1b6 a3=7ffedc40cce0 items=2 ppid=432 pid=3333 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=2 comm="touch" exe="/bin/touch" key="audit-wazuh-w" type=CWD msg=audit(1479982525.380:50):  cwd="/var/log/audit" type=PATH msg=audit(1479982525.380:50): item=0 name="/var/log/audit/tmp_directory1/" inode=399849 dev=ca:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT type=PATH msg=audit(1479982525.380:50): item=1 name="/var/log/audit/tmp_directory1/malware.py" inode=399852 dev=ca:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE type=PROCTITLE msg=audit(1479982525.380:50): proctitle=746F756368002F7661722F6C6F672F61756469742F746D705F6469726563746F7279312F6D616C776172652E7079""", r"""node=localhost type=SYSCALL msg=audit(1479982525.380:50): arch=c000003e syscall=2 success=yes exit=3 a0=7ffedc40d83b a1=941 a2=1b6 a3=7ffedc40cce0 items=2 ppid=432 pid=3333 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=2 comm="touch" exe="/bin/touch" key="audit-wazuh-w" type=CWD msg=audit(1479982525.380:50):  cwd="/var/log/audit" type=PATH msg=audit(1479982525.380:50): item=0 name="/var/log/audit/tmp_directory1/" inode=399849 dev=ca:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT type=PATH msg=audit(1479982525.380:50): item=1 name="/var/log/audit/tmp_directory1/malware.py" inode=399852 dev=ca:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE type=PROCTITLE msg=audit(1479982525.380:50): proctitle=746F756368002F7661722F6C6F672F61756469742F746D705F6469726563746F7279312F6D616C776172652E7079"""),
            'auditd',
            '80790',
            3,
            id='audit_created_audit_file_name',
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


