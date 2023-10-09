# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170562");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-18 12:49:44 +0000 (Mon, 18 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2023-23358", "CVE-2023-23359", "CVE-2023-23360", "CVE-2023-23361");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-23-19, QSA-23-21)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-23358, CVE-2023-23359: Out-of-bounds write vulnerabilities

  - CVE-2023-23360, CVE-2023-23361: NULL pointer dereference vulnerabilities");

  script_tag(name:"impact", value:"If exploited, the vulnerabilities allow authenticated users to
  launch a denial-of-service (DoS) attack via network vector.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h4.5.4 and h5.0.1.");

  script_tag(name:"solution", value:"Update to version QuTS hero h4.5.4.2374 build 20230417,
  h5.0.1.2348 build 20230324 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/de-de/security-advisory/qsa-23-19");
  script_xref(name:"URL", value:"https://www.qnap.com/de-de/security-advisory/qsa-23-21");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h4\.5\.4") {
  if (version_is_less(version: version, test_version: "h4.5.4.2374")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h4.5.4.2374", fixed_build: "20230417");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h4.5.4.2374") &&
     (!build || version_is_less(version: build, test_version: "20230417"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h4.5.4.2374", fixed_build: "20230417");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^h5\.0\.1") {
  if (version_is_less(version: version, test_version: "h5.0.1.2348")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.0.1.2348", fixed_build: "20230324");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.0.1.2348") &&
     (!build || version_is_less(version: build, test_version: "20230324"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.0.1.2348", fixed_build: "20230324");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
