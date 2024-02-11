# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151649");
  script_version("2024-02-07T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-02-07 05:05:18 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-05 07:42:28 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-06 19:57:03 +0000 (Tue, 06 Feb 2024)");

  script_cve_id("CVE-2023-39297", "CVE-2023-45025", "CVE-2023-39302", "CVE-2023-39303",
                "CVE-2023-41273", "CVE-2023-41274", "CVE-2023-41275", "CVE-2023-41276",
                "CVE-2023-41277", "CVE-2023-41278", "CVE-2023-41279", "CVE-2023-41280",
                "CVE-2023-41292", "CVE-2023-45035", "CVE-2023-45036", "CVE-2023-45037",
                "CVE-2023-41281", "CVE-2023-41282", "CVE-2023-41283", "CVE-2023-32967",
                "CVE-2023-45026", "CVE-2023-45027", "CVE-2023-45028", "CVE-2023-47566",
                "CVE-2023-47567", "CVE-2023-47568");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTScloud c5.x < c5.1.5.2651 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-39297: OS command injection

  - CVE-2023-45025: OS command injection

  - CVE-2023-39302: OS command injection

  - CVE-2023-39303: Improper authentication

  - CVE-2023-41273: Heap-based buffer overflow

  - CVE-2023-41274: NULL pointer dereference

  - CVE-2023-41275, CVE-2023-41276, CVE-2023-41277, CVE-2023-41278, CVE-2023-41279, CVE-2023-41280:
  Buffer copy without checking size of input

  - CVE-2023-41292, CVE-2023-45035, CVE-2023-45036, CVE-2023-45037: Multiple buffer copy without
  checking size of input

  - CVE-2023-41281, CVE-2023-41282, CVE-2023-41283: Multiple OS command injection

  - CVE-2023-32967: Incorrect authorization

  - CVE-2023-45026, CVE-2023-45027: Path traversal

  - CVE-2023-45028: Uncontrolled resource consumption (DoS)

  - CVE-2023-47566: OS command injection

  - CVE-2023-47567: OS command injection

  - CVE-2023-47568: SQL injection (SQLi)");

  script_tag(name:"affected", value:"QNAP QuTScloud c5.x.");

  script_tag(name:"solution", value:"Update to version c5.1.5.2651 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-30");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-33");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-38");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-46");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-47");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-53");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-01");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-02");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-04");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-05");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "c5.0.0", test_version_up: "c5.1.5.2651")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "c5.1.5.2651");
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
