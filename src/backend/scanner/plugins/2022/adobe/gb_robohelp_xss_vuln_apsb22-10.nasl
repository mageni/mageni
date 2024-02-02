# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:robohelp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821179");
  script_version("2023-11-24T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-07-13 09:06:05 +0530 (Wed, 13 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 16:36:00 +0000 (Fri, 15 Jul 2022)");

  script_cve_id("CVE-2022-23201");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe RoboHelp XSS Vulnerability (APSB22-10)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_robohelp_nd_robohelp_server_smb_login_detect.nasl");
  script_mandatory_keys("adobe/robohelp/detected");

  script_tag(name:"summary", value:"Adobe RoboHelp is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code on the target system.");

  script_tag(name:"affected", value:"Adobe RoboHelp version 2020.0.7 and prior.");

  script_tag(name:"solution", value:"Update to version 2020.0.8 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/robohelp/apsb22-10.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less_equal(version: vers, test_version: "2020.0.7")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2020.0.8", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
