###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Visual Studio 2017 Multiple Vulnerabilities-July18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813573");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2018-8172", "CVE-2018-8232");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-12 13:08:27 +0530 (Thu, 12 Jul 2018)");
  script_name("Microsoft Visual Studio 2017 Multiple Vulnerabilities-July18");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists,

  - When the software fails to check the source markup of a file for an unbuilt
    project.

  - When Microsoft Macro Assembler improperly validates code logic.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to tamper the code and execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Visual Studio 2017");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8172");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8232");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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
if(!vsVer || vsVer !~ "^15\."){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\VisualStudio\SxS\VS7");
}

else if("x64" >< os_arch){
 key_list = make_list("SOFTWARE\Microsoft\VisualStudio\SxS\VS7", "SOFTWARE\Wow6432Node\Microsoft\VisualStudio\SxS\VS7");
}

foreach key (key_list)
{
  installPath = registry_get_sz(key:key, item:"15.0");
  if(!installPath){
    continue;
  }

  binPath = installPath + "Common7\IDE\PrivateAssemblies\";
  dllVer = fetch_file_version(sysPath:binPath, file_name:"Microsoft.VisualStudio.Setup.dll");
  if(dllVer && dllVer =~ "^1\.1[56]\." && version_is_less(version:dllVer, test_version:"1.16.1193.54969"))
  {
    report = report_fixed_ver(file_checked: binPath + "Microsoft.VisualStudio.Setup.dll",
                              file_version:dllVer, vulnerable_range:"1.15.0 - 1.16.1193.54969");
    security_message(data:report);
    exit(0);
  }
}
exit(0);
