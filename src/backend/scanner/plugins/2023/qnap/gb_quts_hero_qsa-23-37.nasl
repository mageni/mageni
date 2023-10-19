# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151113");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-09 04:10:14 +0000 (Mon, 09 Oct 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-10 20:54:00 +0000 (Tue, 10 Oct 2023)");

  script_cve_id("CVE-2023-32971", "CVE-2023-32972");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-23-37)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer copy without checking size of input vulnerability has
  been reported to affect several QNAP operating systems.");

  script_tag(name:"impact", value:"If exploited, the vulnerability could allow authenticated
  administrators to execute code via a network.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h4.5.x, h5.0.x and h5.1.x.");

  script_tag(name:"solution", value:"Update to version h4.5.4.2476 build 20230728, h5.0.1.2515
  build 20230907, h5.1.0.2424 build 20230609 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-37");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h4\.5\.4") {
  if (version_is_less(version: version, test_version: "h4.5.4.2476")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h4.5.4.2476", fixed_build: "20230728");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h4.5.4.2476") &&
     (!build || version_is_less(version: build, test_version: "20230728"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h4.5.4.2476", fixed_build: "20230728");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^h5\.0\.1") {
  if (version_is_less(version: version, test_version: "h5.0.1.2515")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.0.1.2515", fixed_build: "20230907");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.0.1.2515") &&
     (!build || version_is_less(version: build, test_version: "20230907"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.0.1.2515", fixed_build: "20230907");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^h5\.1\.0") {
  if (version_is_less(version: version, test_version: "h5.1.0.2424")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.1.0.2424", fixed_build: "20230609");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.0.2424") &&
     (!build || version_is_less(version: build, test_version: "20230609"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.1.0.2424", fixed_build: "20230609");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
