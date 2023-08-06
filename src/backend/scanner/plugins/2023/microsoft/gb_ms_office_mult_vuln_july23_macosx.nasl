# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832222");
  script_version("2023-07-14T05:06:08+0000");
  script_cve_id("CVE-2023-33149", "CVE-2023-33158", "CVE-2023-33161", "CVE-2023-33162");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 10:51:38 +0530 (Wed, 12 Jul 2023)");
  script_name("Microsoft Office 2019 Multiple Vulnerabilities (Jul23) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2019 on Mac OSX according to Microsoft security
  update July 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple remote
  code execution and information disclosure vulnerabilities in Microsoft Excel
  and Microsoft Office Graphics.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to execute arbitrary code and disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2019 version 16.74.2 (Build 23062500) and prior on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 16.75 (Build 23070901)
  or later. Please see the references for more information.");

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
  if(version_in_range(version:vers, test_version:"16.17.0", test_version2:"16.74.2")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.75 (Build 23070901)");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
