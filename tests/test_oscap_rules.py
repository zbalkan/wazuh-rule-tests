#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from oscap.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""Apr 12 10:50:32 centos oscap: Evaluation started. Content: /usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml, Profile: xccdf_org.ssgproject.content_profile_standard.""",
            'oscap',
            '81401',
            0,
            id='openscap_evaluation_started',
        ),
        pytest.param(
            r"""Apr 12 10:50:42 centos oscap: Evaluation finished. Return code: 0, Base score 100.000000.""",
            'oscap',
            '81402',
            0,
            id='openscap_evaluation_finished',
        ),
        pytest.param(
            r"""Apr 12 10:50:42 centos oscap: Evaluation finished. Return code: 2, Base score 100.000000.""",
            'oscap',
            '81403',
            0,
            id='openscap_evaluation_finished_with_some_failures',
        ),
        pytest.param(
            r"""oscap: ERROR: OpenSCAP not installed. Details: [Errno 2] No such file or directory""",
            'oscap',
            '81502',
            7,
            id='openscap_error_openscap_not_installed',
        ),
        pytest.param(
            r"""oscap: ERROR: Impossible to execute OpenSCAP...""",
            'oscap',
            '81503',
            7,
            id='openscap_error_impossible_to_execute_openscap',
        ),
        pytest.param(
            r"""oscap: ERROR: File "checklists/ssg-centos7dfa-axccdf.xml" does not exist.""",
            'oscap',
            '81504',
            7,
            id='openscap_error_wrong_configuration_inexistent_policy',
        ),
        pytest.param(
            r"""oscap: ERROR: Parsing file "a.xml". Details: "a.xml:1: parser error : Start tag expected, '<' not found".""",
            'oscap',
            '81505',
            7,
            id='openscap_error_wrong_configuration_invalid_policy',
        ),
        pytest.param(
            r"""oscap: ERROR: Executing profile "standard" of file "checklists/ssg-centos7-xccdf.xml": Return Code: "101" Error: "No such module: eva".""",
            'oscap',
            '81506',
            7,
            id='openscap_error_problem_executing_oscap',
        ),
        pytest.param(
            r"""oscap: ERROR: Profile "kk" does not exist at "checklists/ssg-centos7-xccdf.xml".""",
            'oscap',
            '81507',
            7,
            id='openscap_error_wrong_configuration_inexistent_profile',
        ),
        pytest.param(
            r"""oscap: ERROR: Timeout expired.""",
            'oscap',
            '81508',
            7,
            id='openscap_error_timeout_expired',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "pass", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81521',
            0,
            id='openscap_rule_pass',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "notchecked", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81522',
            0,
            id='openscap_rule_notchecked',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", ...""",
            'oscap',
            '81523',
            0,
            id='openscap_rule_notapplicable',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "fixed", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81524',
            0,
            id='openscap_rule_fixed',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "informational", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81525',
            1,
            id='openscap_rule_informational',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "error", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81526',
            3,
            id='openscap_rule_error',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "unknown", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81527',
            3,
            id='openscap_rule_unknown',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "notselected", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81528',
            0,
            id='openscap_rule_notselected',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "fail", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81529',
            5,
            id='openscap_rule_failed_severity_low',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "fail", severity: "medium", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81530',
            7,
            id='openscap_rule_failed_severity_medium',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "fail", severity: "high", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".""",
            'oscap',
            '81531',
            9,
            id='openscap_rule_failed_severity_high',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "100.000000".""",
            'oscap',
            '81540',
            3,
            id='openscap_report_overview',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "85.835060".""",
            'oscap',
            '81541',
            4,
            id='openscap_report_overview_score_less_than_90',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "75.835060".""",
            'oscap',
            '81542',
            5,
            id='openscap_report_overview_score_less_than_80',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "45.835060".""",
            'oscap',
            '81543',
            7,
            id='openscap_report_overview_score_less_than_50',
        ),
        pytest.param(
            r"""oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "25.835060".""",
            'oscap',
            '81544',
            9,
            id='openscap_report_overview_score_less_than_30',
        ),
        pytest.param(
            r"""oscap: msg: "oval-result", scan-id: "0011477050403", content: "cve-ubuntu-xenial-oval.xml", title: "CVE-2002-2439 on Ubuntu 16.04 LTS (xenial) - low.", id: "oval:com.ubuntu.xenial:def:20022439000", result: "pass", description: "operator new[] sometimes returns pointers to heap blocks which are too small. When a new array is allocated, the C++ run-time has to calculate its size. The product may exceed the maximum value which can be stored in a machine register. This error is ignored, and the truncated value is used for the heap allocation. This may lead to heap overflows and therefore security bugs. (See http://cert.uni-stuttgart.de/advisories/calloc.php for further references.)", profile-title: "vulnerability", reference: "CVE-2002-2439 (https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-2439)".""",
            'oscap',
            '81551',
            0,
            id='openscap_oval_pass',
        ),
        pytest.param(
            r"""oscap: msg: "oval-result", scan-id: "0011477050403", content: "cve-ubuntu-xenial-oval.xml", title: "CVE-2002-2439 on Ubuntu 16.04 LTS (xenial) - low.", id: "oval:com.ubuntu.xenial:def:20022439000", result: "fail", description: "operator new[] sometimes returns pointers to heap blocks which are too small. When a new array is allocated, the C++ run-time has to calculate its size. The product may exceed the maximum value which can be stored in a machine register. This error is ignored, and the truncated value is used for the heap allocation. This may lead to heap overflows and therefore security bugs. (See http://cert.uni-stuttgart.de/advisories/calloc.php for further references.)", profile-title: "patch", reference: "CVE-2002-2439 (https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-2439)".""",
            'oscap',
            '81552',
            7,
            id='openscap_oval_fail',
        ),
        pytest.param(
            r"""oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "95.19".""",
            'oscap',
            '81560',
            3,
            id='openscap_oval_report_overview',
        ),
        pytest.param(
            r"""oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "85.19".""",
            'oscap',
            '81561',
            4,
            id='openscap_oval_report_overview_score_less_than_90',
        ),
        pytest.param(
            r"""oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "75.19".""",
            'oscap',
            '81562',
            5,
            id='openscap_oval_report_overview_score_less_than_80',
        ),
        pytest.param(
            r"""oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "45.19".""",
            'oscap',
            '81563',
            7,
            id='openscap_oval_report_overview_score_less_than_50',
        ),
        pytest.param(
            r"""oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "25.19".""",
            'oscap',
            '81564',
            9,
            id='openscap_oval_report_overview_score_less_than_30',
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


