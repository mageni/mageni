# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150912");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-08-29 02:04:49 +0000 (Tue, 29 Aug 2023)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2023-34972", "CVE-2023-34973");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-23-58, QSA-23-59)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-34972: Information disclosure

  - CVE-2023-34973: Insufficient entropy");

  script_tag(name:"affected", value:"QNAP QTS version 5.0.1 and 5.1.0.");

  script_tag(name:"solution", value:"Update to version 5.0.1.2425 build 20230609, 5.1.0.2444 build
  20230629 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-58");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-59");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5\.0") {
  if (version_is_less(version: version, test_version: "5.0.1.2425")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1.2425", fixed_build: "20230609");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.1.2425") &&
     (!build || version_is_less(version: build, test_version: "20230609"))) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1.2425", fixed_build: "20230609");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^5\.1") {
  if (version_is_less(version: version, test_version: "5.1.0.2444")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.1.0.2444", fixed_build: "20230629");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.1.0.2444") &&
     (!build || version_is_less(version: build, test_version: "20230629"))) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.1.0.2444", fixed_build: "20230629");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
