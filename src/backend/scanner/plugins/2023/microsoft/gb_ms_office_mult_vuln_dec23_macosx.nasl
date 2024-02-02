# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832636");
  script_version("2023-12-14T08:20:35+0000");
  script_cve_id("CVE-2023-36009", "CVE-2023-35619");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 18:58:00 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 11:16:35 +0530 (Wed, 13 Dec 2023)");
  script_name("Microsoft Office for Mac Multiple Vulnerabilities December-23 (Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2019 for Mac according to Microsoft security update
  December 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Microsoft Word Information Disclosure Vulnerability.

  - Microsoft Outlook for Mac Spoofing Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose sensitive information and conduct spoofing attack on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2021 on Mac OS X prior to Version 16.80 (Build 23121017).");

  script_tag(name:"solution", value:"Upgrade to version 16.80 (Build 23121017)
  for Microsoft Office 2021. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(vers =~ "^16\.")
{
  if(version_in_range(version:vers, test_version:"16.54.0", test_version2:"16.79.2")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.80 (Build 23121017)");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
