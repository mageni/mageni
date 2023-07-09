# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832131");
  script_version("2023-06-16T14:09:42+0000");
  script_cve_id("CVE-2023-32029", "CVE-2023-33133", "CVE-2023-33137", "CVE-2023-33131",
                "CVE-2023-33146");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-06-16 14:09:42 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-14 13:40:16 +0530 (Wed, 14 Jun 2023)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities-June23");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Office Click-to-Run update June 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-32029 - Microsoft Excel Remote Code Execution Vulnerability

  - CVE-2023-33133 - Microsoft Excel Remote Code Execution Vulnerability

  - CVE-2023-33137 - Microsoft Excel Remote Code Execution Vulnerability

  - CVE-2023-33131 - Microsoft Outlook Remote Code Execution Vulnerability

  - CVE-2023-33146 - Microsoft Office Remote Code Execution Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct remote code execution, denial of service and security bypass on an
  affected system.");

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
if(!officeVer || officeVer !~ "^16\."){
  exit(0);
}

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2305 (Build 16501.20210)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.16501.20210")){
    fix = "Version 2305 (Build 16501.20210)";
  }
}
## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2302 (Build 16130.20500)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.16130.20580")){
    fix = "Version 2302 (Build 16130.20580)";
  }
}

## Semi-Annual Enterprise Channel: Version 2202 (Build 14931.21000)
## Semi-Annual Enterprise Channel: Version 2208 (Build 15601.20660)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14931.21024")){
    fix = "Version 2202 (Build 14931.21024)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.15601.0", test_version2:"16.0.15601.20679")){
    fix = "Version 2208 (Build 15601.20680)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.16130.0", test_version2:"16.0.16130.20579")){
    fix = "Version 2302 (Build 16130.20580)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
