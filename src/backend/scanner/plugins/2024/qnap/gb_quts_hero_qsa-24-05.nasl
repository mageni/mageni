# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151648");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-05 05:46:45 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 03:42:42 +0000 (Thu, 08 Feb 2024)");

  script_cve_id("CVE-2023-47567", "CVE-2023-47568");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-24-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-47567: An OS command injection could allow authenticated administrators to execute
  commands via a network.

  - CVE-2023-47568: An SQL injection could allow authenticated users to inject malicious code via a
  network.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h4.5.x and h5.1.x.");

  script_tag(name:"solution", value:"Update to version h4.5.4.2626 build 20231225,
  h5.1.5.2647 build 20240118 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-05");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h4\.5") {
  if (version_is_less(version: version, test_version: "h4.5.4.2626")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h4.5.4.2626", fixed_build: "20231225");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h4.5.4.2626") &&
     (!build || version_is_less(version: build, test_version: "20231225"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h4.5.4.2626", fixed_build: "20231225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^h5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.5.2647")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.5.2647", fixed_build: "20240118");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.5.2647") &&
     (!build || version_is_less(version: build, test_version: "20240118"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.5.2647", fixed_build: "20240118");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
