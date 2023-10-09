# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832283");
  script_version("2023-09-22T16:08:59+0000");
  script_cve_id("CVE-2023-36796", "CVE-2023-36794", "CVE-2023-36792", "CVE-2023-36793");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-09-22 16:08:59 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-14 11:44:15 +0530 (Thu, 14 Sep 2023)");
  script_name("Microsoft Visual Studio Multiple Vulnerabilities-04 - September23");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Update September-2023.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple remote
  code execution, elevation of privilege and denial of service vulnerabilities in
  Microsoft Visual Studio.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial of service, elevate privileges and execute arbitrary code
  on an affected system.");

  script_tag(name:"affected", value:"Microsoft Visual Studio 2017 version 15.9 prior to 15.9.57.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.57");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_mandatory_keys("Microsoft/VisualStudio/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

vsVer = get_kb_item("Microsoft/VisualStudio/Ver");
if(!vsVer || vsVer !~ "^16\."){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}


foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    vsname = registry_get_sz(key:key + item, item:"DisplayName");
    if(vsname =~ "^Visual Studio.*2017$")
    {
      install = registry_get_sz(key:key + item, item:"InstallLocation");
      if(install)
        vsversion = fetch_file_version(sysPath:install, file_name:"Common7\IDE\devenv.exe");
      if(!vsversion)
        vsversion = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(!vsversion)
        continue;

      if(version_in_range(version:vsversion, test_version:"15.9", test_version2:"15.9.33801.238")) {
        fix = "Visual Studio 2017 version 15.9.57";
        report = report_fixed_ver(installed_version:vsversion, fixed_version:fix);
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
