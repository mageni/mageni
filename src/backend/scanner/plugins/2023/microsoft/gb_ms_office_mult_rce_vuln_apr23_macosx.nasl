# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826956");
  script_version("2023-04-13T10:09:33+0000");
  script_cve_id("CVE-2023-28311", "CVE-2023-28285");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-04-13 10:09:33 +0000 (Thu, 13 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 11:14:20 +0530 (Wed, 12 Apr 2023)");
  script_name("Microsoft Office 2019 Multiple RCE Vulnerabilities Apr-23 (Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2019 on Mac OSX according to Microsoft security
  update April 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to vulnerabilities
  in some unknown processing of the component Graphics and an unknown code of
  the component Word.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2019 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 16.72 (Build 23040900)
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

if(!vers = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(vers =~ "^16\.")
{
  if(version_in_range(version:vers, test_version:"16.17.0", test_version2:"16.71")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.72 (Build 23040900)");
    security_message(data:report);
    exit(0);
  }
}

exit(99);
