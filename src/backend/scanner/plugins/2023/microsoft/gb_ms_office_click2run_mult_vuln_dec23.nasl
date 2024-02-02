# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832637");
  script_version("2023-12-14T08:20:35+0000");
  script_cve_id("CVE-2023-36009", "CVE-2023-35636");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 18:58:00 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 11:16:35 +0530 (Wed, 13 Dec 2023)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (December23)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Office Click-to-Run update December 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  information disclosure vulnerabilities in Microsoft Outlook and Word.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\.")
  exit(0);

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2311 (Build 17029.20108)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel") {
  if(version_is_less(version:officeVer, test_version:"16.0.17029.20108"))
    fix = "Version 2311 (Build 17029.20108)";
}
## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2308 (Build 16731.20460)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)") {
  if(version_is_less(version:officeVer, test_version:"16.0.16731.20460"))
    fix = "Version 2308 (Build 16731.20460)";
}

## Semi-Annual Enterprise Channel: Version 2208 (Build 15601.20832)
## Semi-Annual Enterprise Channel: Version 2302 (Build 16130.20868)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel") {
  if(version_in_range(version:officeVer, test_version:"16.0.15601.0", test_version2:"16.0.15601.20831")) {
    fix = "Version 2208 (Build 15601.20832)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.16130.0", test_version2:"16.0.16130.20867")) {
    fix = "Version 2302 (Build 16130.20868)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
