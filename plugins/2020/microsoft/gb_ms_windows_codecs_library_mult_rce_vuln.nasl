# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817300");
  script_version("2020-07-09T12:15:58+0000");
  script_cve_id("CVE-2020-1425", "CVE-2020-1457");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-07-10 11:44:30 +0000 (Fri, 10 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-02 17:39:49 +0530 (Thu, 02 Jul 2020)");
  script_name("Microsoft Windows Codecs Library Multiple Remote Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft updates for Windows Codecs Library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple errors
  in the way that Microsoft Windows codecs library handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1709 for 32-bit Systems

  - Microsoft Windows 10 Version 1709 for x64-based Systems

  - Microsoft Windows 10 Version 1803 for 32-bit Systems

  - Microsoft Windows 10 Version 1803 for x64-based Systems

  - Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows 10 Version 1903 for 32-bit Systems

  - Microsoft Windows 10 Version 1903 for x64-based Systems

  - Microsoft Windows 10 Version 1909 for 32-bit Systems

  - Microsoft Windows 10 Version 1909 for x64-based Systems

  - Microsoft Windows 10 Version 2004 for 32-bit Systems

  - Microsoft Windows 10 Version 2004 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates and will be
  automatically installed. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1457");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1425");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


edgeVer = "";
gdiVer = "";
sysPath = "";
os_arch = "";
maxVer = "";

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

gdiVer = fetch_file_version(sysPath:sysPath, file_name:"Gdiplus.dll");
if(!gdiVer){
  exit(0);
}

#1709 == 11.0.16299
#1903/1909 = 11.0.18362
#1809 = 11.0.17763
#1803 = 11.0.17134
#2004 = 10.0.19041
if(edgeVer =~ "^11\.0\.17134" ||
   edgeVer =~ "^11\.0\.17763" ||
   edgeVer =~ "^11\.0\.18362" ||
   edgeVer =~ "^11\.0\.16299" ||
   gdiVer =~ "^10\.0\.19041")
{

  os_arch = get_kb_item("SMB/Windows/Arch");
  if(!os_arch){
    exit(0);
  }

  if("x86" >< os_arch){
    key_list = make_list("SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\");
  } else if("x64" >< os_arch){
    key_list = make_list("SOFTWARE\Wow6432Node\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\",
                         "SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\");
  }

  foreach key(key_list)
  {
    foreach item (registry_enum_keys(key:key))
    {
      if("HEVCVideoExtension" >< item)
      {
        version = eregmatch(pattern:"HEVCVideoExtension_([0-9.]+)_", string:item);
        if(!isnull(version[1]))
        {
          if(isnull(maxVer)){
            maxVer = version[1];
          } else {
            if(version_is_greater(version:version[1], test_version:maxVer)){
              maxVer = version[1];
            } else {
              continue;
            }
          }
        }
      }
    }
  }

  if(!isnull(maxVer)  && maxVer =~ "[0-9.]+")
  {
    if(version_is_less(version:maxVer, test_version:"1.0.31822.0"))
    {
      report = report_fixed_ver(installed_version:maxVer, fixed_version:"1.0.31822.0", vulnerable_range:"Less than 1.0.31822.0");
      security_message(data:report);
      exit(0);
    }
  }
}
