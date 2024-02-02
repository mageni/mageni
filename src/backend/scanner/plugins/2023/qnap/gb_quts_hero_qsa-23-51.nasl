# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151255");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-07 02:57:42 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 15:29:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2023-39301");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero SSRF Vulnerability (QSA-23-51)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to a server-side request forgery (SSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A server-side request forgery (SSRF) vulnerability has been
  reported to affect several QNAP operating system versions. If exploited, the vulnerability could
  allow authenticated users to read application data via a network.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.0.x and h5.1.x.");

  script_tag(name:"solution", value:"Update to version QuTS hero h5.0.1.2515 build 20230907,
  h5.1.1.2488 build 20230812 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-51");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.0") {
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

if (version =~ "^h5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.1.2488")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.1.1.2488", fixed_build: "20230812");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.1.2488") &&
     (!build || version_is_less(version: build, test_version: "20230812"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "h5.1.1.2488", fixed_build: "20230812");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
