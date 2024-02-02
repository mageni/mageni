# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151480");
  script_version("2024-01-11T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-01-11 05:05:45 +0000 (Thu, 11 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-09 03:19:10 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 14:00:00 +0000 (Fri, 07 Apr 2023)");

  script_cve_id("CVE-2022-43634", "CVE-2023-39294", "CVE-2023-39296");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-23-22, QSA-23-54, QSA-23-64)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-43634: Vulnerability in Netatalk

  - CVE-2023-39294: An OS command injection vulnerability has been reported to affect certain QNAP
  operating system versions. If exploited, the vulnerability could allow authenticated
  administrators to execute commands via a network.

  - CVE-2023-39296: A prototype pollution vulnerability has been reported to affect certain QNAP
  operating system versions. If exploited, the vulnerability could allow remote users to override
  existing attributes with ones that have an incompatible type, which may cause the system to
  crash.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.1.x.");

  script_tag(name:"solution", value:"Update to version h5.1.3.2578 build 20231110 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-22");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-54");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-64");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.3.2578")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.1.3.2578", fixed_build: "20231110");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.3.2578") &&
     (!build || version_is_less(version: build, test_version: "20231110"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.1.3.2578", fixed_build: "20231110");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
