# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170694");
  script_version("2023-11-23T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-11-23 05:06:17 +0000 (Thu, 23 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-14 10:37:15 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-21 03:08:00 +0000 (Tue, 21 Nov 2023)");

  script_cve_id("CVE-2023-23367");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS OS Command Injection Vulnerability (QSA-23-24)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to an OS command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, the vulnerability could allow authenticated
  administrators to execute commands via a network.");

  script_tag(name:"affected", value:"QNAP QTS version 5.0.x.");

  script_tag(name:"solution", value:"Update to version 5.0.1.2376 build 20230421 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/QSA-23-24");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5\.0") {
  if (version_is_less(version: version, test_version:"5.0.1.2376")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.1.2376", fixed_build: "20230421");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.1.2376") &&
     (!build || version_is_less(version: build, test_version: "20230421"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.1.2376", fixed_build: "20230421");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
