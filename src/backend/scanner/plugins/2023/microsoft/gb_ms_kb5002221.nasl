# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832035");
  script_version("2023-04-13T10:09:33+0000");
  script_cve_id("CVE-2023-28295", "CVE-2023-28287");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-04-13 10:09:33 +0000 (Thu, 13 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 10:56:21 +0530 (Wed, 12 Apr 2023)");
  script_name("Microsoft Publisher 2016 Multiple Vulnerabilities (KB5002221)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002221");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a Remote Code Execution
  vulnerability in Microsoft Office.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and compromise the target system.");

  script_tag(name:"affected", value:"Microsoft Publisher 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002221");
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
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Publisher/Installed/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer && exeVer =~ "^16.*")
{
  if(version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.5391.0999"))
  {
    report = report_fixed_ver(file_checked: exePath + "\mspub.exe",
                                file_version:exeVer, vulnerable_range:"16.0 - 16.0.5391.0999");
     security_message(data:report);
     exit(0);
  }
}

exit(99);
