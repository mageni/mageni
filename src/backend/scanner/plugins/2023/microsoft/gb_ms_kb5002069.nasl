# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832231");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2023-33152");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 10:51:38 +0530 (Wed, 12 Jul 2023)");
  script_name("Microsoft Office 2013 Service Pack 1 Remote Code Execution Vulnerability (KB5002069)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002069");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified remote code
  execution vulnerability in Microsoft ActiveX.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to execute arbitrary code on the target system.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002069");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

vers = get_kb_item("MS/Office/Ver");
if(!vers || vers !~ "^15\.")
  exit(0);

if(!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
}
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list) {
  msPath = registry_get_sz(key:key, item:"CommonFilesDir");
  if(msPath) {
    offPath = msPath + "\Microsoft Shared\Office15";
    msdllVer = fetch_file_version(sysPath:offPath, file_name:"riched20.dll");

    if(msdllVer && msdllVer =~ "^15\.") {
      if(version_is_less(version:msdllVer, test_version:"15.0.5389.1000")) {
        report = report_fixed_ver( file_checked:offPath + "\riched20.dll",
                                   file_version:msdllVer, vulnerable_range:"15.0 - 15.0.5389.0999");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
