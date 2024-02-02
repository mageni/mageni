# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:bridge_cc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832701");
  script_version("2023-11-24T16:09:32+0000");
  script_cve_id("CVE-2023-44327", "CVE-2023-44328", "CVE-2023-44329");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-24 16:09:32 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-22 15:20:00 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-19 19:14:57 +0530 (Sun, 19 Nov 2023)");
  script_name("Adobe Bridge Multiple Vulnerabilities (APSB23-57) - Windows");

  script_tag(name:"summary", value:"Adobe Bridge is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An Access of Uninitialized Pointer.

  - An Use-After-Free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution and memory leak on an affected system.");

  script_tag(name:"affected", value:"Adobe Bridge 13.0.4 and earlier versions,
  14.0.0 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update to version 13.0.5 or 14.0.1 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb23-57.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect.nasl");
  script_mandatory_keys("Adobe/Bridge/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"14.0", test_version_up:"14.0.1")) {
  fix = "14.0.1 or later";
}
else if(version_in_range_exclusive(version:vers, test_version_lo:"13.0", test_version_up:"13.0.4")) {
  fix = "13.0.5 or later";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
