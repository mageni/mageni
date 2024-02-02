# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832796");
  script_version("2024-01-31T14:37:46+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-23211", "CVE-2024-23206", "CVE-2024-23213", "CVE-2024-23222");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-31 14:37:46 +0000 (Wed, 31 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-30 14:32:15 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-23 10:41:20 +0530 (Tue, 23 Jan 2024)");
  script_name("Apple Safari Security Update (HT214056)");

  script_tag(name:"summary", value:"Apple Safari is multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper memory handling, checks.

  - Improper handling of user preferences.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow attackers to conduct arbitrary code execution and information
  disclosure on an affected system.");

  script_tag(name:"affected", value:"Apple Safari versions before 17.3");

  script_tag(name:"solution", value:"Upgrade to version 17.3 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214056");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

safVer = infos["version"];
safPath = infos["location"];

if(version_is_less(version:safVer, test_version:"17.3")) {
  report = report_fixed_ver(installed_version:safVer, fixed_version:"17.3", install_path:safPath);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
