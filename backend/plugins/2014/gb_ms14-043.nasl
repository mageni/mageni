###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Media Center Remote Code Execution Vulnerability (2978742)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802079");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-4060");
  script_bugtraq_id(69093);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-08-13 11:57:50 +0530 (Wed, 13 Aug 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Windows Media Center Remote Code Execution Vulnerability (2978742)");


  script_tag(name:"summary", value:"This host is missing an critical security update according to
Microsoft Bulletin MS14-043");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MCPlayer fails to properly clean up resources after a CSyncBasePlayer
object is deleted.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to arbitrary code in the
context of the current user.");
  script_tag(name:"affected", value:"Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

Windows Media Center for

  - Microsoft Windows 8 x32/x64 Edition

  - Microsoft Windows 8.1 x32/x64 Edition

Windows Media Center TV Pack for Windows Vista x32/x64 Edition");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2978742");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-043");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win8:1, win8x64:1, win8_1:1, win8_1x64:1,
                   winVista:3, winVistax64:3) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## http://msdn.microsoft.com/en-us/library/ms815274.aspx
media_center_ver = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\Current" +
                                       "Version\Media Center", item:"Ident");

if(!media_center_ver){
  exit(0);
}

mcplayer_ver = fetch_file_version(sysPath:sysPath, file_name:"ehome\Mcplayer.dll");
if(!mcplayer_ver){
  exit(0);
}

if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:mcplayer_ver, test_version:"6.1.7601.18523") ||
     version_in_range(version:mcplayer_ver, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22732")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win8x64:1, win8_1:1, win8_1x64:1) > 0)
{
  ## Only Professional edition is affected for Windows 8 and 8.1
  os_edition = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                               item:"EditionID");
  if("Professional">!< os_edition){
    exit(0);
  }

  if(hotfix_check_sp(win8:1, win8x64:1) > 0)
  {
    if(version_is_less(version:mcplayer_ver, test_version:"6.2.9200.17045") ||
       version_in_range(version:mcplayer_ver, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21161")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
  {
    if(version_is_less(version:mcplayer_ver, test_version:"6.3.9600.17224")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

## Currently not supporting for Vista 64 bit
else if(hotfix_check_sp(winVista:3) > 0)
{
  if("5.1" >!< media_center_ver){
    exit(0);
  }

  if(version_is_less(version:mcplayer_ver, test_version:"6.1.1000.18324")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
