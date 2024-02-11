# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151636");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-05 03:59:50 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 03:50:56 +0000 (Thu, 08 Feb 2024)");

  script_cve_id("CVE-2023-39297", "CVE-2023-45025");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-23-30, QSA-23-47)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-39297: An OS command injection vulnerability has been reported to affect certain QNAP
  operating system versions. If exploited, the vulnerability could allow authenticated users to
  execute commands via a network.

  - CVE-2023-45025: An OS command injection vulnerability has been reported to affect certain QNAP
  operating system versions. If exploited, the vulnerability could allow users to execute commands
  via a network when the system is in a certain configuration.");

  script_tag(name:"affected", value:"QNAP QTS version 4.5.x and 5.1.x.");

  script_tag(name:"solution", value:"Update to version 4.5.4.2627 build 20231225,
  5.1.4.2596 build 20231128 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-30");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-47");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^4\.5") {
  if (version_is_less(version: version, test_version:"4.5.4.2627")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.5.4.2627", fixed_build: "20231225");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.5.4.2627") &&
     (!build || version_is_less(version: build, test_version: "20231225"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.5.4.2627", fixed_build: "20231225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^5\.1") {
  if (version_is_less(version: version, test_version:"5.1.4.2596")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.1.4.2596", fixed_build: "20231128");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.1.4.2596") &&
     (!build || version_is_less(version: build, test_version: "20231128"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.1.4.2596", fixed_build: "20231128");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
