###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Media Center Remote Code Execution Vulnerabilities (2604926)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901209");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-10-12 16:01:32 +0200 (Wed, 12 Oct 2011)");
  script_bugtraq_id(49943);
  script_cve_id("CVE-2011-2009");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Media Center Remote Code Execution Vulnerabilities (2604926)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46404");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2579692");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2579686");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-076");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  in the context of the user running the application.");
  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Media Center TV Pack for Windows Vista.");
  script_tag(name:"insight", value:"The flaw is due to Windows Media Player improperly restricting the
  path used when loading external libraries.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-076.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2) <= 0){
  exit(0);
}

winName = get_kb_item("SMB/WindowsName");
if("Windows Vista" >< winName)
{
  ## http://msdn.microsoft.com/en-us/library/ms815274.aspx
  mediaTVPackVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\Current" +
                                       "Version\Media Center", item:"Ident");
  if(hotfix_missing(name:"2579686") == 0 &&
     hotfix_missing(name:"2579692") == 0){
    exit(0);
  }
}
else if ("Windows 7" >< winName)
{
  if(hotfix_missing(name:"2579686") == 0){
    exit(0);
  }
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\Psisdecd.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if ("5.1" >< mediaTVPackVer)
  {
    ## for Windows Media Center TV Pack for Windows Vista
    if(version_is_less(version:dllVer, test_version:"6.6.1000.18310")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"6.6.6002.18000", test_version2:"6.6.6002.18495") ||
       version_in_range(version:dllVer, test_version:"6.6.6002.22000", test_version2:"6.6.6002.22685")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.6.7600.16867")||
     version_in_range(version:dllVer, test_version:"6.6.7600.20000", test_version2:"6.6.7600.21029")||
     version_in_range(version:dllVer, test_version:"6.6.7601.17000", test_version2:"6.6.7601.17668")||
     version_in_range(version:dllVer, test_version:"6.6.7601.21000", test_version2:"6.6.7601.21791")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
