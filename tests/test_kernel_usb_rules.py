#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from kernel_usb.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Mar 23 15:04:52 manager kernel: usb 1-1: New USB device found, idVendor=0930, idProduct=6544',
            'kernel',
            '81101',
            3,
            id='kernel_usb_attach_usb',
        ),
        pytest.param(
            'Mar 23 15:04:52 manager kernel: [62828.333722] usb 1-1: New USB device found, idVendor=0930, idProduct=6544',
            'kernel',
            '81101',
            3,
            id='kernel_usb_attach_usb_with_kernel_id',
        ),
        pytest.param(
            'Mar 15 23:14:34 manager kernel: [ 195.634715] usb 1-1: New USB device found, idVendor=0bda, idProduct=568a, bcdDevice=65.10',
            'kernel',
            '81101',
            3,
            id='kernel_usb_attach_usb_with_kernel_id_and_blank_spaces',
        ),
        pytest.param(
            'Mar 23 15:05:23 manager kernel: usb 1-1: USB disconnect, device number 2',
            'kernel',
            '81102',
            3,
            id='kernel_usb_disconnect_usb',
        ),
        pytest.param(
            'Mar 23 15:05:23 manager kernel: [62859.373865] usb 1-1: USB disconnect, device number 2',
            'kernel',
            '81102',
            3,
            id='kernel_usb_disconnect_usb_with_kernel_id',
        ),
        pytest.param(
            'Mar 23 15:05:23 manager kernel: [  259.373865] usb 1-1: USB disconnect, device number 2',
            'kernel',
            '81102',
            3,
            id='kernel_usb_disconnect_usb_with_kernel_id_and_blank_spaces',
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


