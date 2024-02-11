# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151640");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-05 04:41:29 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 03:55:41 +0000 (Thu, 08 Feb 2024)");

  script_cve_id("CVE-2023-32967");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Authorization Vulnerability (QSA-24-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to an incorrect authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, the vulnerability could allow authenticated users
  to bypass intended access restrictions via a network.");

  script_tag(name:"affected", value:"QNAP QTS version 4.5.x.");

  script_tag(name:"solution", value:"Update to version 4.5.4.2627 build 20231225 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-01");

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

exit(99);
