# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832170");
  script_version("2023-08-24T05:06:01+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-36884");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-09 10:40:13 +0530 (Wed, 09 Aug 2023)");
  script_name("Microsoft Publisher 2013 Remote Code Execution Vulnerability (KB5002391)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002391");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a Remote Code Execution Vulnerability in
  Microsoft Publisher");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary commands and compromise the target system.");

  script_tag(name:"affected", value:"Microsoft Publisher 2013.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002391");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Publisher/Version");
  exit(0);

}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

exeVer = get_kb_item("SMB/Office/Publisher/Version");
if(!exeVer) {
  exit(0);
}

exePath = get_kb_item("SMB/Office/Publisher/Installed/Path");
if(!exePath) {
  exePath = "Unable to fetch the install path";
}

if(exeVer && exeVer =~ "^15.*") {
  if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.5579.1000")) {
    report = report_fixed_ver(file_checked: exePath + "\mspub.exe",
                                file_version:exeVer, vulnerable_range:"15.0 - 15.0.5579.1000");

     security_message(port:0, data:report);
     exit(0);
  }
}

exit(99);
