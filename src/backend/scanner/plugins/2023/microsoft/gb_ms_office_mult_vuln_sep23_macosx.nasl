# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832285");
  script_version("2023-09-22T16:08:59+0000");
  script_cve_id("CVE-2023-36766", "CVE-2023-36762", "CVE-2023-36767", "CVE-2023-27911");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-09-22 16:08:59 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-14 11:44:15 +0530 (Thu, 14 Sep 2023)");
  script_name("Microsoft Office 2019 Multiple Vulnerabilities (September23) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2019 on Mac OSX according to Microsoft security
  update September 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due,

  - Microsoft Office Security Feature Bypass Vulnerability.

  - Heap buffer overflow vulnerability in Autodesk FBX SDK 2020 or prior.

  - Microsoft Excel Information Disclosure Vulnerability.

  - Microsoft Word Remote Code Execution Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to execute arbitrary code, disclose sensitive information and bybass security
  restrictions on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2019 version prior to 16.77 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 16.77 (Build 23091003)
  for Microsoft Office 2019. Please see the references for more information.");

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

if(!vers = get_kb_item("MS/Office/MacOSX/Ver"))
  exit(0);


if(vers =~ "^16\.") {
  if(version_in_range(version:vers, test_version:"16.17.0", test_version2:"16.76.2")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.77");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
