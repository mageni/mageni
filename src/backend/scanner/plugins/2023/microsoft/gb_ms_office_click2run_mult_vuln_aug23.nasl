# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832250");
  script_version("2023-08-24T05:06:01+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-36896", "CVE-2023-35371", "CVE-2023-36893", "CVE-2023-35372",
                "CVE-2023-36865", "CVE-2023-36866", "CVE-2023-36897", "CVE-2023-36895",
                "CVE-2023-36884");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-10 12:47:48 +0530 (Thu, 10 Aug 2023)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (August23)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Office Click-to-Run update August 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple remote code execution Vulnerabilities.

  - Microsoft Spoofing Vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  conduct remote code execution and spoofing on an affected system.");

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

## Version 2307 (Build 16626.20170)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel") {
  if(version_is_less(version:officeVer, test_version:"16.0.16626.20170"))
    fix = "Version 2307 (Build 16626.20170)";
}
## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2302 (Build 16130.20714)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)") {
  if(version_is_less(version:officeVer, test_version:"16.0.16130.20714"))
    fix = "Version 2302 (Build 16130.20714)";
}

## Semi-Annual Enterprise Channel: Version 2202 (Build 14931.21040) Version 2202 (Build 14931.21078)
## Semi-Annual Enterprise Channel: Version 2208 (Build 15601.20706) Version 2208 (Build 15601.20742)
## Semi-Annual Enterprise Channel: Version 2302 (Build 16130.20644) Version 2302 (Build 16130.20714)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel") {
  if(version_is_less(version:officeVer, test_version:"16.0.14931.21078")) {
    fix = "Version 2202 (Build 14931.21078)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.15601.0", test_version2:"16.0.15601.20741")) {
    fix = "Version 2208 (Build 15601.20742)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.16130.0", test_version2:"16.0.16130.20713")) {
    fix = "Version 2302 (Build 16130.20714)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
