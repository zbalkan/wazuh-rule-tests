#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from named.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""Aug 29 15:33:13 ns3 named[464]: client 217.148.39.3#1036: query (cache) denied""",
            'named',
            '12108',
            5,
            id='query_cache_denied_1',
        ),
        pytest.param(
            r"""Aug 29 15:33:13 ns3 named[464]: client 217.148.39.4#32769: query (cache) denied""",
            'named',
            '12108',
            5,
            id='query_cache_denied_2',
        ),
        pytest.param(
            r"""Aug 29 15:33:13 ns3 named[464]: client 217.148.39.3#1036: query (cache) denied""",
            'named',
            '12108',
            5,
            id='query_cache_denied_3',
        ),
        pytest.param(
            r"""Aug 29 15:33:13 ns3 named[464]: client 217.148.39.3#1036: query (cache)""",
            'named',
            '12108',
            5,
            id='query_cache_denied_5',
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
            r"""Aug 29 15:33:13 ns3 name[464]: client 217.148.39.4#32769: query (cache) denied""",
            'named',
            '12108',
            5,
            id='query_cache_denied_4',
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


