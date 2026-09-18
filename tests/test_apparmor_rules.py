#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from apparmor.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Jun 24 10:35:29 hostname kernel: [49787.970285] audit: type=1400 audit(1403598929.839:88986): apparmor="ALLOWED" operation="getattr" profile="/usr/sbin/dovecot//null-1//null-2//null-4a6" name="/home/admin/mails/new/" pid=19973 comm="imap" requested_mask="r" denied_mask="r" fsuid=1003 ouid=1003',
            'kernel',
            '52001',
            0,
            id='ignore_allowed_or_status',
        ),
        pytest.param(
            'Jun 23 20:46:15 hostname kernel: [   11.103248] audit: type=1400 audit(1403549175.177:2): apparmor="STATUS" operation="profile_load" name="/sbin/klogd" pid=2185 comm="apparmor_parser"',
            'kernel',
            '52001',
            0,
            id='apparmor_allowed_or_status',
        ),
        pytest.param(
            'Jul 14 11:03:47 hostname kernel: [ 8665.951930] type=1400 audit(1405328627.702:54): apparmor="DENIED" operation="open" profile="/usr/bin/evince" name="/etc/xfce4/defaults.list" pid=16418 comm="evince" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0',
            'kernel',
            '52002',
            3,
            id='apparmor_denied',
        ),
        pytest.param(
            'Jun 16 17:37:39 hostname kernel: [891880.587989] audit: type=1400 audit(1314853822.672:33649): apparmor="DENIED" operation="mknod" parent=27250 profile="/usr/lib/apache2/mpm-prefork/apache2//example.com" name="/usr/share/wordpress/1114140474e5f13bea68a4.tmp" pid=27289 comm="apache2" requested_mask="c" denied_mask="c" fsuid=33 ouid=33',
            'kernel',
            '52004',
            4,
            id='apparmor_denied_mknod_operation',
        ),
        pytest.param(
            'Jun 16 17:37:39 hostname kernel: [891880.587989] audit: type =1400 audit(1315353795.331:33657): apparmor="DENIED" operation="exec" parent=14952 profile="/usr/lib/apache2/mpm-prefork/apache2//example.com" name="/usr/lib/sm.bin/sendmail" pid=14953 comm="sh" requested_mask="x" denied_mask="x" fsuid=33 ouid=0',
            'kernel',
            '52003',
            5,
            id='apparmor_denied_exec_operation',
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


