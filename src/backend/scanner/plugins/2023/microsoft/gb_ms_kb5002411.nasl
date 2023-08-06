# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832307");
  script_version("2023-07-14T05:06:08+0000");
  script_cve_id("CVE-2023-33150");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 13:27:16 +0530 (Wed, 12 Jul 2023)");
  script_name("Microsoft Word 2013 Service Pack 1 Security Feature Bypass Vulnerability (KB5002411)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5002411");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"A security feature bypass vulnerability exists in Microsoft Word.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  conduct remote code execution on the target system.");

  script_tag(name:"affected", value:"Microsoft Word 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002411");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");

exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer =~ "^15\." && version_is_less(version:exeVer, test_version:"15.0.5571.0999")){
  report = report_fixed_ver(file_checked:exePath + "winword.exe", file_version:exeVer, vulnerable_range:"15.0 - 15.0.5571.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);