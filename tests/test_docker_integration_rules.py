#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from docker_integration.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "container", "Action": "create", "Actor": {"ID": "acedfgh123456789abcdef", "Attributes": {"image": "nginx:latest", "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>", "name": "wazuh-test-container"}}, "scope": "local", "time": 1766395777, "timeNano": 1766395777009588769}}""",
            'json',
            '87901',
            3,
            id='docker_container_created',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "container", "Action": "start", "Actor": {"ID": "acedfgh123456789abcdef", "Attributes": {"image": "nginx:latest", "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>", "name": "wazuh-test-container"}}, "scope": "local", "time": 1766395777, "timeNano": 1766395777009588769}}""",
            'json',
            '87903',
            3,
            id='docker_container_started',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "container", "Action": "stop", "Actor": {"ID": "acedfgh123456789abcdef", "Attributes": {"image": "nginx:latest", "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>", "name": "wazuh-test-container"}}, "scope": "local", "time": 1766397293, "timeNano": 1766397293655089317}}""",
            'json',
            '87904',
            3,
            id='docker_container_stopped',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "container", "Action": "die", "Actor": {"ID": "acedfgh123456789abcdef", "Attributes": {"execDuration": "20", "exitCode": "0", "image": "nginx:latest", "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>", "name": "wazuh-test-container"}}, "scope": "local", "time": 1766397293, "timeNano": 1766397293673509492}}""",
            'json',
            '87924',
            7,
            id='docker_container_die',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "container", "Action": "destroy", "Actor": {"ID": "acedfgh123456789abcdef", "Attributes": {"image": "nginx:latest", "name": "wazuh-test-container"}}, "scope": "local", "time": 1766397300, "timeNano": 1766397300123456789}}""",
            'json',
            '87902',
            5,
            id='docker_container_destroyed',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "container", "Action": "delete", "Actor": {"ID": "acedfgh123456789abcdef", "Attributes": {"image": "nginx:latest", "name": "wazuh-test-container"}}, "scope": "local", "time": 1766397310, "timeNano": 1766397310987654321}}""",
            'json',
            '87921',
            7,
            id='docker_container_deleted',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "container", "Action": "exec_start: bash ", "Actor": {"ID": "acedfgh123456789abcdef", "Attributes": {"image": "nginx:latest", "name": "wazuh-test-container"}}, "scope": "local", "time": 1766395800, "timeNano": 1766395800111222333}}""",
            'json',
            '87908',
            5,
            id='docker_shell_session_started',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "volume", "Action": "create", "Actor": {"ID": "volumeacedfgh123", "Attributes": {"driver": "local", "name": "wazuh-volume"}}, "scope": "local", "time": 1766395900, "timeNano": 1766395900444555666}}""",
            'json',
            '87913',
            3,
            id='docker_volume_created',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "volume", "Action": "destroy", "Actor": {"ID": "volumeacedfgh123", "Attributes": {"driver": "local", "name": "wazuh-volume"}}, "scope": "local", "time": 1766396000, "timeNano": 1766396000777888999}}""",
            'json',
            '87914',
            7,
            id='docker_volume_destroyed',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "network", "Action": "create", "Actor": {"ID": "networkacedfgh456", "Attributes": {"name": "wazuh-network", "type": "bridge"}}, "scope": "local", "time": 1766396100, "timeNano": 1766396100111222333}}""",
            'json',
            '87930',
            3,
            id='docker_network_created',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "network", "Action": "destroy", "Actor": {"ID": "networkacedfgh456", "Attributes": {"name": "wazuh-network", "type": "bridge"}}, "scope": "local", "time": 1766396200, "timeNano": 1766396200444555666}}""",
            'json',
            '87931',
            5,
            id='docker_network_destroyed',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "image", "Action": "pull", "Actor": {"ID": "imageacedfgh789", "Attributes": {"name": "nginx:latest"}}, "scope": "local", "time": 1766396300, "timeNano": 1766396300777888999}}""",
            'json',
            '87932',
            3,
            id='docker_image_pulled',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "container", "Action": "pause", "Actor": {"ID": "acedfgh123456789abcdef", "Attributes": {"image": "nginx:latest", "name": "wazuh-test-container"}}, "scope": "local", "time": 1766396400, "timeNano": 1766396400123456789}}""",
            'json',
            '87905',
            3,
            id='docker_container_paused',
        ),
        pytest.param(
            r"""{"integration": "docker", "docker": {"Type": "container", "Action": "unpause", "Actor": {"ID": "acedfgh123456789abcdef", "Attributes": {"image": "nginx:latest", "name": "wazuh-test-container"}}, "scope": "local", "time": 1766396500, "timeNano": 1766396500987654321}}""",
            'json',
            '87906',
            3,
            id='docker_container_unpaused',
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


