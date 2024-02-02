# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832740");
  script_version("2023-12-29T16:09:56+0000");
  script_cve_id("CVE-2023-47074", "CVE-2023-47075", "CVE-2023-47063");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 13:35:00 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-14 11:03:34 +0530 (Thu, 14 Dec 2023)");
  script_name("Adobe Illustrator Multiple Vulnerabilities (APSB23-68) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Illustrator is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An Out-of-bounds Read error.

  - An Out-of-bounds Write error.

  - An Use After Free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution on an affected system.");

  script_tag(name:"affected", value:"Adobe Illustrator 2023 prior to 27.9.1 and
  Adobe Illustrator 2024 prior to 28.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Illustrator 2023 27.9.1
  or Adobe Illustrator 2024 28.1. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/illustrator/apsb23-68.html");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Illustrator/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^27\.") {
  if(version_is_less(version:vers, test_version:"27.9.1")) {
    fix = "27.9.1";
    installed_ver = "Adobe Illustrator 2023";
  }
}

else if(vers =~ "^28\.") {
  if(version_is_less(version:vers, test_version:"28.1")) {
    fix = "28.1";
    installed_ver = "Adobe Illustrator 2024";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
