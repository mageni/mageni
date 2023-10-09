# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832249");
  script_version("2023-08-17T05:05:20+0000");
  script_cve_id("CVE-2023-36896", "CVE-2023-36895", "CVE-2023-35371");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-08-17 05:05:20 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-10 12:47:48 +0530 (Thu, 10 Aug 2023)");
  script_name("Microsoft Office 2019 Multiple Vulnerabilities (August23) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2019 on Mac OSX according to Microsoft security
  update August 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple remote
  code execution vulnerabilities in Microsoft Excel, Microsoft Outlook and
  Microsoft Office components.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2019 version 16.75.2 (Build 23072301) and prior on Mac OS X.");

  script_tag(name:"solution", value:"No known solution is available as of 10th August, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"NoneAvailable");
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
  if(version_in_range(version:vers, test_version:"16.17.0", test_version2:"16.75.2")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"None");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
