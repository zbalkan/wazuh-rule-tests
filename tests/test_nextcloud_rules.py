#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log, send_multiple_logs

pytestmark = pytest.mark.wazuh_logtest


# Converted from nextcloud.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""{"reqId":"XaCAfP1v4@1xpIqlElMIVgAAAAk","level":1,"time":"October 11, 2019 13:15:40","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"GET","url":"\/index.php\/logout?requesttoken=RPYdKvrWwtB859EZQyfK%2F2DIu5l7HAqMrrNlcMzKoaM%3D%3AFLdvYq6atZJKgeFgEUSglQql0fsQaCHD68EjFKicleg%3D","message":"Logout occurred","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""",
            'json',
            '88210',
            3,
            id='nextcloud_logout_successful',
        ),
        pytest.param(
            r"""{"reqId":"XaQ6fxNN-waxXQIsoJHOTQAAAAE","level":1,"time":"October 14, 2019 09:06:07","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"POST","url":"\/index.php\/login?user=admin","message":"Login successful: \"admin\"","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""",
            'json',
            '88211',
            3,
            id='nextcloud_authentication_successful',
        ),
        pytest.param(
            r"""{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""",
            'json',
            '88212',
            6,
            id='nextcloud_authentication_failed',
        ),
        pytest.param(
            r"""{"reqId":"XaCDUP1v4@1xpIqlElMIaQAAAAk","level":1,"time":"October 11, 2019 13:27:44","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"GET","url":"\/remote.php\/webdav\/Nextcloud%20Manual.pdf","message":"File accessed: \"\/Nextcloud Manual.pdf\"","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""",
            'json',
            '88213',
            3,
            id='nextcloud_file_accessed',
        ),
        pytest.param(
            r"""{"reqId":"XaCDuMT03XAQReilx1Z76QAAAAU","level":1,"time":"October 11, 2019 13:29:28","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"PUT","url":"\/remote.php\/webdav\/logo.jpg","message":"File created: \"\/\/logo.jpg\"","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""",
            'json',
            '88214',
            3,
            id='nextcloud_file_created',
        ),
        pytest.param(
            r"""{"reqId":"XaCDX3wkGUtETLC8cVWzdwAAAAI","level":1,"time":"October 11, 2019 13:27:59","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"DELETE","url":"\/remote.php\/dav\/files\/admin\/logo.png","message":"File deleted: \"\/logo.png\"","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""",
            'json',
            '88215',
            3,
            id='nextcloud_file_deleted',
        ),
        pytest.param(
            r"""{"reqId":"XaCCwMT03XAQReilx1Z75gAAAAU","level":1,"time":"October 11, 2019 13:25:20","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"GET","url":"\/index.php\/core\/preview?fileId=1780&x=1920&y=1080&a=true","message":"Preview accessed: \"\/logo.png\" (width: \"1920\", height: \"1080\" crop: \"\", mode: \"fill\")","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""",
            'json',
            '88216',
            3,
            id='nextcloud_preview_accessed',
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
            (r"""{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""", r"""{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""", r"""{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""", r"""{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""", r"""{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""", r"""{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""", r"""{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}""", r"""{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}"""),
            'json',
            '88203',
            10,
            id='nextcloud_brute_force',
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


