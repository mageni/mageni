# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151111");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-09 03:43:30 +0000 (Mon, 09 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-26 13:41:00 +0000 (Tue, 26 Sep 2023)");

  script_cve_id("CVE-2023-23363");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS RCE Vulnerability (QSA-23-25)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer copy without checking size of input vulnerability has
  been reported to affect certain legacy versions of QTS.");

  script_tag(name:"impact", value:"If exploited, the vulnerability could allow clients to execute
  code via unspecified vectors");

  script_tag(name:"affected", value:"QNAP QTS version 4.3.6, 4.3.4, 4.3.3 and 4.2.6.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20230621, 4.3.3.2420 build
  20230621, 4.3.4.2451 build 20230621, 4.3.6.2441 build 20230621 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-25");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^4\.2") {
  if (version_is_less(version: version, test_version: "4.2.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6", fixed_build: "20230621");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.2.6") &&
     (!build || version_is_less(version: build, test_version: "20230621"))) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6", fixed_build: "20230621");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.3") {
  if (version_is_less(version: version, test_version: "4.3.3.2420")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3.2420", fixed_build: "20230621");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.3.2420") &&
     (!build || version_is_less(version: build, test_version: "20230621"))) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3.2420", fixed_build: "20230621");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.4") {
  if (version_is_less(version: version, test_version: "4.3.4.2451")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4.2451", fixed_build: "20230621");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.4.2451") &&
     (!build || version_is_less(version: build, test_version: "20230621"))) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4.2451", fixed_build: "20230621");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.6") {
  if (version_is_less(version: version, test_version: "4.3.6.2441")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6.2441", fixed_build: "20230621");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.6.2441") &&
     (!build || version_is_less(version: build, test_version: "20230621"))) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6.2441", fixed_build: "20230621");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
