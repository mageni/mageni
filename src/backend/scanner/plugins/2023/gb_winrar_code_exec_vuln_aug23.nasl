# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rarlab:winrar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832263");
  script_version("2023-10-06T16:09:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-38831");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-31 11:33:32 +0530 (Thu, 31 Aug 2023)");
  script_name("RARLabs WinRAR Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"WinRAR is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a ZIP archive may
  include a benign file and also a folder that has the same name as the benign
  file, and the contents of the folder (which may include executable content)
  are processed during an attempt to access only the benign file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"RARLabs WinRAR before 6.23 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 6.23 or later,
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_winrar_detect.nasl");
  script_mandatory_keys("WinRAR/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"6.23")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.23", install_path:path);

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
