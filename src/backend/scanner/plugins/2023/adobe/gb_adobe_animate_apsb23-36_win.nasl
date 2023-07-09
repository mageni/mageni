# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:animate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832139");
  script_version("2023-07-03T05:06:07+0000");
  script_cve_id("CVE-2023-29321");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-03 05:06:07 +0000 (Mon, 03 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-06-15 12:59:12 +0530 (Thu, 15 Jun 2023)");
  script_name("Adobe Animate Code Execution Vulnerabilities (APSB23-36)-Windows");

  script_tag(name:"summary", value:"Adobe Animate is prone to a Code Execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a use-after-free
  error in Adobe Animate.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Adobe Animate 2022 version 22.0.9 and earlier versions and
  2023 version 23.0.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade Adobe Animate 2022 to 22.0.10 or
  later, 2023 to 23.0.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/animate/apsb23-36.html");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_animate_detect_win.nasl");
  script_mandatory_keys("Adobe/Animate/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"23.0", test_version2:"23.0.1") ||
   version_in_range(version:vers, test_version:"22.0", test_version2:"22.0.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"22.0.10 or 23.0.2 or later", install_path:path);
  security_message(data: report);
  exit(0);
}

exit(99);
