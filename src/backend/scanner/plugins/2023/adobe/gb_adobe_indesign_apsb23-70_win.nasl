# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832741");
  script_version("2023-12-29T16:09:56+0000");
  script_cve_id("CVE-2023-47076", "CVE-2023-47077");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 13:35:00 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-14 11:48:18 +0530 (Thu, 14 Dec 2023)");
  script_name("Adobe InDesign Multiple Vulnerabilities (APSB23-70) - Windows");

  script_tag(name:"summary", value:"Adobe Indesign is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - NULL Pointer Dereference.

  - Out-of-bounds Read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct DoS attacks and memory leak on an affected system.");

  script_tag(name:"affected", value:"Adobe InDesign prior to 18.5.1 and prior
  to 19.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 18.5.1 or 19.1 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb23-70.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.4.2")) {
  fix = "18.5.1";
}
else if(vers =~ "^19\.") {
  if(version_is_less(version:vers, test_version:"19.1")) {
    fix = "19.1";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
