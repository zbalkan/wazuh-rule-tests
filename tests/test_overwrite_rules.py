#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from overwrite.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule overwritten',
            'ow_test',
            '999911',
            12,
            id='overwrite_success',
        ),
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule overwritten',
            'ow_test',
            '999912',
            12,
            id='overwrite_success_and_child_matches_1',
        ),
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule overwritten',
            'ow_test',
            '999912',
            12,
            id='overwrite_success_and_child_matches_2',
        ),
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule overwritten',
            'ow_test',
            '999912',
            12,
            id='overwrite_success_and_child_matches_3',
        ),
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 2 - Parent rule',
            'ow_test',
            '999914',
            12,
            id='overwrite_if_matched_sid_1',
        ),
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 2 - Parent rule',
            'ow_test',
            '999914',
            12,
            id='overwrite_if_matched_sid_2',
        ),
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 2 - Parent rule',
            'ow_test',
            '999914',
            12,
            id='overwrite_if_matched_sid_3',
        ),
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 3 - Parent rule',
            'ow_test',
            '999917',
            12,
            id='overwrite_if_matched_group_1',
        ),
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 3 - Parent rule',
            'ow_test',
            '999917',
            12,
            id='overwrite_if_matched_group_2',
        ),
        pytest.param(
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 3 - Parent rule',
            'ow_test',
            '999917',
            12,
            id='overwrite_if_matched_group_3',
        ),
        pytest.param(
            'May 27 14:49:04 testUser ow_test[13244]: TEST 4 - Overwrite and list test',
            'ow_test',
            '999918',
            5,
            id='overwrite_list',
        ),
        pytest.param(
            "Apr 14 13:38:51 testUser test_overwrite_field[13244]: Test example 'TEST5' field",
            'test_overwrite',
            '999919',
            6,
            id='overwrite_field',
        ),
        pytest.param(
            "Apr 14 13:38:51 testUser test_overwrite_field[13244]: Test example 'MULTIPLE' field",
            'test_overwrite',
            '999920',
            3,
            id='multiple_overwrite',
        ),
        pytest.param(
            "Apr 14 13:38:51 testUser test_overwrite_field[13244]: Test example 'TEST7' field",
            'test_overwrite',
            '999922',
            3,
            id='overwrite_with_if_sid',
        ),
        pytest.param(
            "Apr 14 13:38:51 testUser test_overwrite_field[13244]: Test example 'TEST8' field",
            'test_overwrite',
            '999924',
            3,
            id='overwrite_with_if_level',
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
            'Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule to be overwritten',
            'ow_test',
            '999911',
            12,
            id='do_not_match_overwritten_rule',
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


