# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151371");
  script_version("2023-12-15T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-11 03:58:06 +0000 (Mon, 11 Dec 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 16:14:00 +0000 (Wed, 13 Dec 2023)");

  script_cve_id("CVE-2023-32968", "CVE-2023-32975");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-23-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-32968: Buffer copy without checking size of input

  - CVE-2023-32975: Buffer copy without checking size of input");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.0.x and h5.1.x.");

  script_tag(name:"solution", value:"Update to version QuTS hero h5.0.1.2515 build 20230907,
  h5.1.2.2534 build 20230927 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-07");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.0") {
  if (version_is_less(version: version, test_version: "h5.0.1.2515")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.0.1.2515", fixed_build: "20230907");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.0.1.2515") &&
     (!build || version_is_less(version: build, test_version: "20230907"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.0.1.2515", fixed_build: "20230907");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^h5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.2.2534")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.2.2534", fixed_build: "20230927");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.2.2534") &&
     (!build || version_is_less(version: build, test_version: "20230927"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.2.2534", fixed_build: "20230927");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
