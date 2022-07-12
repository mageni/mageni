###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Remote Code Execution Vulnerability (2706726)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902841");
  script_version("2019-05-03T12:31:27+0000");
  script_bugtraq_id(53861);
  script_cve_id("CVE-2012-1855");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-06-13 09:09:09 +0530 (Wed, 13 Jun 2012)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (2706726)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49418");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2706726");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027149");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-038");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code.");
  script_tag(name:"affected", value:"Microsoft .NET Framework 4
  Microsoft .NET Framework 3.5.1
  Microsoft .NET Framework 2.0 Service Pack 2");
  script_tag(name:"insight", value:"The flaw is due to an error within the framework when handling
  pointers and can be exploited to corrupt memory via a specially crafted
  web page.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-038.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    if("v4.0.30319" >< path){
      dllv4 = fetch_file_version(sysPath:path, file_name:"system.windows.forms.dll");
    }

    if("v2.0.50727" >< path){
      dllv2 = fetch_file_version(sysPath:path, file_name:"system.windows.forms.dll");
    }
  }
}

## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista,
##  Windows Server 2008, Windows 7, and Windows Server 2008 R2
if(dllv4 &&
  (version_in_range(version:dllv4, test_version:"4.0.30319.000", test_version2:"4.0.30319.277") ||
   version_in_range(version:dllv4, test_version:"4.0.30319.500", test_version2:"4.0.30319.559")))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
if(dllv2 && (hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0))
{
  if(version_in_range(version:dllv2, test_version:"2.0.50727.0000", test_version2:"2.0.50727.4976") ||
     version_in_range(version:dllv2, test_version:"2.0.50727.5700", test_version2:"2.0.50727.5723") ||
     version_in_range(version:dllv2, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5459"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 2.0 SP 2 on Windows Vista Service and Windows Server 2008
if(dllv2 && (hotfix_check_sp(winVista:3, win2008:3) > 0))
{
  if(version_in_range(version:dllv2, test_version:"2.0.50727.0000", test_version2:"2.0.50727.4227") ||
     version_in_range(version:dllv2, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5723"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
if(dllv2 && (hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0))
{
  if(version_in_range(version:dllv2, test_version:"2.0.50727.0000", test_version2:"2.0.50727.3636") ||
     version_in_range(version:dllv2, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5723"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 4.5 Beta on Windows 7 , Windows 2008 and Windows Server 2008 R2
if(dllv4 && (hotfix_check_sp(win7:2, win2008:3, win7x64:2, win2008r2:2) > 0))
{
  if(version_in_range(version:dllv4, test_version:"4.0.30319.17000", test_version2:"4.0.30319.17450") ||
     version_in_range(version:dllv4, test_version:"4.0.30319.17500", test_version2:"4.0.30319.17542"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
