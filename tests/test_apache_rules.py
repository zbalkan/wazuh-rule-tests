#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from apache.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""[error] [client 80.230.208.105] Directory index forbidden by rule: /home/""",
            'apache-errorlog',
            '30106',
            5,
            id='apache_attempt_to_access_forbidden_directory_index',
        ),
        pytest.param(
            r"""[error] [client 64.94.163.159] Client sent malformed Host header""",
            'apache-errorlog',
            '30107',
            6,
            id='apache_code_red_attack',
        ),
        pytest.param(
            r"""[error] [client 66.31.142.16] File does not exist: /var/www/html/default.ida""",
            'apache-errorlog',
            '30112',
            0,
            id='apache_attempt_to_access_an_non_existent_file',
        ),
        pytest.param(
            r"""[notice] Apache configured""",
            'apache-errorlog',
            '30103',
            0,
            id='apache_notice_messages_grouped',
        ),
        pytest.param(
            r"""[Fri Dec 13 06:59:54 2013] [error] [client 12.34.65.78] PHP Notice:""",
            'apache-errorlog',
            '30101',
            0,
            id='apache_apache_2_2_error_messages_grouped',
        ),
        pytest.param(
            r"""[Tue Sep 30 11:30:13.262255 2014] [core:error] [pid 20101] [client 99.47.227.95:34567] AH00037: Symbolic link not allowed or link target not accessible: /usr/share/awstats/icon/mime/document.png""",
            'apache-errorlog',
            '30301',
            0,
            id='apache_apache_2_4_error_messages_grouped_1',
        ),
        pytest.param(
            r"""[Tue Sep 30 12:11:21.258612 2014] [ssl:error] [pid 30473] AH02032: Hostname www.example.com provided via SNI and hostname ssl://www.example.com provided via HTTP are different""",
            'apache-errorlog',
            '30301',
            0,
            id='apache_apache_2_4_error_messages_grouped_2',
        ),
        pytest.param(
            r"""[Tue Sep 30 12:24:22.891366 2014] [proxy:warn] [pid 2331] [client 77.127.180.111:54082] AH01136: Unescaped URL path matched ProxyPass; ignoring unsafe nocanon, referer: http://www.easylinker.co.il/he/links.aspx?user=bguyb""",
            'apache-errorlog',
            '30302',
            0,
            id='apache_apache_2_4_warn_messages_grouped',
        ),
        pytest.param(
            r"""[Tue Sep 30 14:25:44.895897 2014] [authz_core:error] [pid 31858] [client 99.47.227.95:38870] AH01630: client denied by server configuration: /var/www/example.com/docroot/""",
            'apache-errorlog',
            '30305',
            5,
            id='apache_attempt_to_access_forbidden_file_or_directory',
        ),
        pytest.param(
            r"""[Thu Oct 23 15:17:55.926067 2014] [ssl:info] [pid 18838] [client 36.226.119.49:2359] AH02008: SSL library error 1 in handshake (server www.example.com:443)""",
            'apache-errorlog',
            '30100',
            0,
            id='apache_messages_grouped_1',
        ),
        pytest.param(
            r"""[Thu Oct 23 15:17:55.926123 2014] [ssl:info] [pid 18838] SSL Library Error: error:1407609B:SSL routines:SSL23_GET_CLIENT_HELLO:https proxy request -- speaking HTTP to HTTPS port!?""",
            'apache-errorlog',
            '30100',
            0,
            id='apache_messages_grouped_2',
        ),
        pytest.param(
            r"""[Sun Nov 23 18:49:01.713508 2014] [:error] [pid 15816] [client 141.8.147.9:51507] PHP Notice:  A non well formed numeric value encountered in /path/to/file.php on line 123""",
            'apache-errorlog',
            '30318',
            5,
            id='apache_php_notices_in_apache_2_4_errorlog',
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


