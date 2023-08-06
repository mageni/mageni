# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832157");
  script_version("2023-07-14T05:06:08+0000");
  script_cve_id("CVE-2023-33149");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 15:10:49 +0530 (Wed, 12 Jul 2023)");
  script_name("Microsoft Office 2016 Graphics Remote Code Execution Vulnerability (KB5002419)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002419");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of user-supplied input in the Microsoft Office.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the target system.");

  script_tag(name:"affected", value:"Microsoft Office 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002419");
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

officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer) {
  exit(0);
}

if(officeVer =~ "^16\.") {
  os_arch = get_kb_item("SMB/Windows/Arch");
  if("x86" >< os_arch) {
    key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
  }
  else if("x64" >< os_arch) {
    key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                          "SOFTWARE\Microsoft\Windows\CurrentVersion");
  }

  foreach key(key_list) {
    propath = registry_get_sz(key:key, item:"ProgramFilesDir");
    if(propath) {
      offPath = propath + "\Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\Office16";
      offexeVer = fetch_file_version(sysPath:offPath, file_name:"mso.dll");
      if(!offexeVer) {
        continue ;
      }

      if(offexeVer =~ "^16\." && version_is_less(version:offexeVer, test_version:"16.0.5404.1000")) {
        report = report_fixed_ver(file_checked:offPath + "\mso.dll",
                 file_version:offexeVer, vulnerable_range:"16.0 - 16.0.5404.0999");
        security_message(data:report);
        exit(0);
      }
    }
  }
}
exit(99);
