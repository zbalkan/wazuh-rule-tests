#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from api.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 400""",
            'wazuh-api',
            '410',
            4,
            id='api_bad_request',
        ),
        pytest.param(
            r"""2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 401""",
            'wazuh-api',
            '411',
            8,
            id='api_unauthorized',
        ),
        pytest.param(
            r"""2021/10/04 15:23:55 INFO: unknown_user 172.18.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.001s: 403""",
            'wazuh-api',
            '412',
            7,
            id='api_s_response_code_returned_error_permission_denied',
        ),
        pytest.param(
            r"""2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 404""",
            'wazuh-api',
            '413',
            4,
            id='resource_not_found',
        ),
        pytest.param(
            r"""2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 405""",
            'wazuh-api',
            '414',
            4,
            id='invalid_http_method',
        ),
        pytest.param(
            r"""2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 406""",
            'wazuh-api',
            '415',
            4,
            id='invalid_content_type',
        ),
        pytest.param(
            r"""2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 413""",
            'wazuh-api',
            '416',
            4,
            id='maximum_request_body_size_exceeded',
        ),
        pytest.param(
            r"""2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 429""",
            'wazuh-api',
            '417',
            7,
            id='max_number_of_requests_per_minute_reached',
        ),
        pytest.param(
            r"""2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 500""",
            'wazuh-api',
            '418',
            4,
            id='internal_error',
        ),
        pytest.param(
            r"""2021/04/20 16:00:35 INFO: wazuh 127.0.0.1 "PUT /agents/group" with parameters {"group_id": "group1", "agents_list":629,650,654,682"} and body {} done in 0.075s: 200""",
            'wazuh-api',
            '407',
            5,
            id='api_s_put_method_event',
        ),
        pytest.param(
            r"""2021/10/05 10:33:14 INFO: testing 172.21.0.1 "GET /agents/stats/distinct" with parameters {"fields": "os.name"} and body {} done in 0.009s: 200""",
            'wazuh-api',
            '406',
            4,
            id='api_s_get_method_event_success',
        ),
        pytest.param(
            r"""2021/10/07 10:46:00 INFO: wazuh-wui 172.16.1.1 "POST /groups" with parameters {} and body {"group_id": "NewGroup_1"} done in 0.009s: 200""",
            'wazuh-api',
            '409',
            5,
            id='api_post_method_event_success',
        ),
        pytest.param(
            r"""2021/10/07 10:32:33 INFO: unknown_user 172.16.1.1 "DELETE /agents" with parameters {} and body {} done in 0.001s: 200""",
            'wazuh-api',
            '408',
            7,
            id='api_delete_method_event_success',
        ),
        pytest.param(
            r"""2021/10/05 10:30:21 INFO: Generated private key file in WAZUH_PATH/api/configuration/ssl/server.key""",
            'wazuh-api-info',
            '421',
            3,
            id='api_info_informative_event',
        ),
        pytest.param(
            r"""2021/10/04 15:23:55 WARNING: something wrong happened""",
            'wazuh-api-info',
            '422',
            5,
            id='api_info_warning_event',
        ),
        pytest.param(
            r"""2021/10/04 15:23:55 ERROR: Something bad happened""",
            'wazuh-api-info',
            '423',
            8,
            id='api_info_error_event',
        ),
        pytest.param(
            r"""2021/10/04 15:23:55 ERROR: IP blocked due to exceeded number of logins attempts: 172.18.0.1""",
            'wazuh-api-info',
            '428',
            10,
            id='api_info_ip_blocked',
        ),
        pytest.param(
            r"""2021/10/05 10:30:21 CRITICAL: Generated private key file in WAZUH_PATH/api/configuration/ssl/server.key""",
            'wazuh-api-info',
            '424',
            12,
            id='api_info_critical_event',
        ),
        pytest.param(
            r"""2021/10/05 10:33:15 INFO: testing 172.21.0.1 "POST /security/user/authenticate" with parameters {} and body {} done in 0.354s: 200""",
            'wazuh-api',
            '426',
            4,
            id='api_authentication_success',
        ),
        pytest.param(
            r"""2022/02/03 10:37:36 INFO: wazuh (d8466023fdec3f1310679989d8827eee) 172.20.0.1 "POST /security/user/authenticate/run_as" with parameters {"raw": "true"} and body {"user_name": "test", "is_reserved": false, "is_hidden": false, "is_internal_user": true, "user_requested_tenant": "__user__", "backend_roles": [""], "custom_attribute_names": [], "tenants": {"test": true, "global_tenant": true, "admin_tenant": true}, "roles": ["own_index", "all_access"]} done in 0.309s: 200""",
            'wazuh-api',
            '426',
            4,
            id='api_authentication_success_with_hash',
        ),
        pytest.param(
            r"""2021/10/05 10:33:15 INFO: testing 172.21.0.1 "POST /security/user/authenticate" with parameters {} and body {} done in 0.354s: 400""",
            'wazuh-api',
            '427',
            7,
            id='api_authentication_failure',
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


