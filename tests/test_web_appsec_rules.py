#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from web_appsec.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /wp-comments-post.php HTTP/1.1" 403 181 "-" "Googlebot/1""",
            'web-accesslog',
            '31501',
            6,
            id='wordpress_comment_spam_coming_from_a_fake_search_engine_ua_1',
        ),
        pytest.param(
            r"""10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /wp-comments-post.php HTTP/1.1" 403 181 "-" "msnbot/1""",
            'web-accesslog',
            '31501',
            6,
            id='wordpress_comment_spam_coming_from_a_fake_search_engine_ua_2',
        ),
        pytest.param(
            r"""10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /wp-comments-post.php HTTP/1.1" 403 181 "-" "BingBot/1""",
            'web-accesslog',
            '31501',
            6,
            id='wordpress_comment_spam_coming_from_a_fake_search_engine_ua_3',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /examplethumb.php?src=example.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31502',
            6,
            id='timthumb_vulnerability_exploit_attempt',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /example.php/login.php?cPath= HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31503',
            6,
            id='oscommerce_login_php_bypass_attempt',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /admin/example.php/login.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31504',
            6,
            id='oscommerce_file_manager_login_php_bypass_attempt',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /example/cache/externalexample.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31505',
            6,
            id='timthumb_backdoor_access_attempt',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /examplecart.php?exampletemplatefile=../ HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31506',
            6,
            id='cart_php_directory_transversal_attempt',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "ZmEu"''',
            'web-accesslog',
            '31508',
            6,
            id='blacklisted_user_agent_known_malicious_user_agent_1',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "libwww-perl/1.1 (X11)"''',
            'web-accesslog',
            '31508',
            6,
            id='blacklisted_user_agent_known_malicious_user_agent_2',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "the beast"''',
            'web-accesslog',
            '31508',
            6,
            id='blacklisted_user_agent_known_malicious_user_agent_3',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "Morfeus"''',
            'web-accesslog',
            '31508',
            6,
            id='blacklisted_user_agent_known_malicious_user_agent_4',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "ZmEu (X11)"''',
            'web-accesslog',
            '31508',
            6,
            id='blacklisted_user_agent_known_malicious_user_agent_5',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "Nikto (X11)"''',
            'web-accesslog',
            '31508',
            6,
            id='blacklisted_user_agent_known_malicious_user_agent_6',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "w3af.sourceforge.net (X11)"''',
            'web-accesslog',
            '31508',
            6,
            id='blacklisted_user_agent_known_malicious_user_agent_7',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /example/wp-login.php HTTP/1.1" 200 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31509',
            3,
            id='cms_wordpress_or_joomla_login_attempt_1',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /administrator HTTP/1.1" 200 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31509',
            3,
            id='cms_wordpress_or_joomla_login_attempt_2',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /index.html? HTTP/1.1" 200 4617 "-" "Wget/1.15 (linux-gnu)"''',
            'web-accesslog',
            '31511',
            0,
            id='blacklisted_user_agent_wget',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /example/uploadify.php?src=http://example.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31512',
            6,
            id='uploadify_vulnerability_exploit_attempt',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET example/delete.php?board_skin_path=http://example.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31513',
            6,
            id='bbs_delete_php_exploit_attempt',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET example/shell.php?cmd= HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31514',
            6,
            id='simple_shell_php_command_execution',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /phpMyAdmin/scripts/setup.php HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"''',
            'web-accesslog',
            '31515',
            6,
            id='phpmyadmin_scans_looking_for_setup_php',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /db/config.php.swp HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"''',
            'web-accesslog',
            '31516',
            6,
            id='suspicious_url_access_1',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /db/config.php.bak HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"''',
            'web-accesslog',
            '31516',
            6,
            id='suspicious_url_access_2',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /db/.htaccess HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"''',
            'web-accesslog',
            '31516',
            6,
            id='suspicious_url_access_3',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /server-status HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"''',
            'web-accesslog',
            '31516',
            6,
            id='suspicious_url_access_4',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /.ssh HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"''',
            'web-accesslog',
            '31516',
            6,
            id='suspicious_url_access_5',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /.history HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"''',
            'web-accesslog',
            '31516',
            6,
            id='suspicious_url_access_6',
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
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST / HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31530',
            3,
            id='post_request_received',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /wp-admin HTTP/1.1" 200 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31531',
            0,
            id='ignoring_often_post_requests_inside_wp_admin_and_admin_1',
        ),
        pytest.param(
            r'''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /admin HTTP/1.1" 200 181 "-" "Mozilla/5.0 (X11)"''',
            'web-accesslog',
            '31531',
            0,
            id='ignoring_often_post_requests_inside_wp_admin_and_admin_2',
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


