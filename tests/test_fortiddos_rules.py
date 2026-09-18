#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from fortiddos.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            '2021-05-27T23:59:59.998837-03:00 12.34.56.78 devid=FGXXXXXXX date=2021-05-28 time=00:00:00 tz=ART type=attack subtype="ips" spp=4 evecode=2 evesubcode=27 description="TCP invalid flag combination " dir=1 protocol=6 sip=0.0.0.0 dip=12.34.56.79 dropcount=30 subnetid=95 facility=Local0 level=Notice direction=inbound spp_name="YYYYY" subnet_name="ZZZZZ" sppoperatingmode=detection severity="high"',
            'fortiddos-like',
            '44629',
            7,
            id='fortigate_ips_high_severity',
        ),
        pytest.param(
            '2021-05-27T23:59:59.998837-03:00 12.34.56.78 devid=FGXXXXXXX date=2021-05-28 time=00:00:00 tz=ART type=attack subtype="ips" spp=4 evecode=2 evesubcode=27 description="TCP invalid flag combination " dir=1 protocol=6 sip=0.0.0.0 dip=12.34.56.79 dropcount=30 subnetid=95 facility=Local0 level=Notice direction=inbound spp_name="YYYYY" subnet_name="ZZZZZ" sppoperatingmode=detection severity="low"',
            'fortiddos-like',
            '44630',
            3,
            id='fortigate_ips_low_severity',
        ),
        pytest.param(
            '2021-05-27T23:59:59.998837-03:00 12.34.56.78 devid=FGXXXXXXX date=2021-05-28 time=00:00:00 tz=ART type=attack subtype="ips" spp=4 evecode=2 evesubcode=27 description="TCP invalid flag combination " dir=1 protocol=6 sip=0.0.0.0 dip=12.34.56.79 dropcount=30 subnetid=95 facility=Local0 level=Notice direction=inbound spp_name="YYYYY" subnet_name="ZZZZZ" sppoperatingmode=detection severity="medium"',
            'fortiddos-like',
            '44631',
            5,
            id='fortigate_ips_medium_severity',
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


