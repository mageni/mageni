###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Privilege Elevation Vulnerability (2769324)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902939");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-0001", "CVE-2013-0002", "CVE-2013-0003", "CVE-2013-0004");
  script_bugtraq_id(57124, 57126, 57114, 57113);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-01-09 10:02:42 +0530 (Wed, 09 Jan 2013)");
  script_name("Microsoft .NET Framework Privilege Elevation Vulnerability (2769324)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51777/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2769324");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2742613");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2742595");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2756921");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2756920");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2742599");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2742598");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2756919");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2756918");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2742601");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2742596");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2742597");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2742604");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2742607");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-004");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary code
  with the privileges of the currently logged-in user. Failed attacks will
  cause denial-of-service conditions.");
  script_tag(name:"affected", value:"Microsoft .NET Framework 1.0 SP3, 1.1 SP1, 2.0 SP2, 3.0, 3.5, 3.5.1, 4 and 4.5");
  script_tag(name:"insight", value:"- An error within the System Drawing namespace of Windows Forms when handling
  pointers can be exploited to bypass CAS (Code Access Security) restrictions and disclose information.

  - An error within WinForms when handling certain objects can be exploited to
    cause a buffer overflow.

  - A boundary error within the System.DirectoryServices.Protocols namespace
    when handling objects can be exploited to cause a buffer overflow.

  - A double construction error within the framework does not validate object
    permissions and can be exploited via a specially crafted XAML Browser
    Application (XBAP) or an untrusted .NET application.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-004.");
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
  if(path && "\Microsoft.NET\Framework" >< path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"System.dll");
    if(dllVer)
    {
      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008,
      ##  Windows 7 and and Windows Server 2008 R2
      if(version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1000")||
         version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2000"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4.5 on Windows 7 SP1 and Windows Server 2008 R2 SP 1
      ##  Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18020")||
          version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19028")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5466")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5739")||
          version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4984")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4234")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.5739")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if((hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3643")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.5739")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 1.1 Service Pack 1 on Windows XP, Windows Server 2003, Windows Vista and Windows Server 2008
      if((hotfix_check_sp(xp:4, win2003:3, win2003x64:3, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2501")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

## Microsoft .NET Framework 1.1 Service Pack 1 when used with
foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"mscorlib.dll");
    if(dllVer)
    {
      if(hotfix_check_sp(win2003:3) > 0)
      {
        ## Microsoft .NET Framework 1.1 Service Pack 1
        if(version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2501"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"All Assemblies In");
  if(path){
    dllv3 = fetch_file_version(sysPath:path, file_name:"system.identitymodel.dll");
  }
}

## .NET Framework 3.0 Service Pack 2 on Windows XP and Windows Server 2003
if(dllv3 && (hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.0.4506.4000", test_version2:"3.0.4506.4036") ||
     version_in_range(version:dllv3, test_version:"3.0.4506.5000", test_version2:"3.0.4506.5844"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 3.0 Service Pack 2 on Windows Vista and Windows Server 2008
if(dllv3 && (hotfix_check_sp(winVista:3, win2008:3) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.0.4506.4000", test_version2:"3.0.4506.4213") ||
     version_in_range(version:dllv3, test_version:"3.0.4506.5000", test_version2:"3.0.4506.5846"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
if(dllv3 && (hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.0.4506.5400", test_version2:"3.0.4506.5451") ||
     version_in_range(version:dllv3, test_version:"3.0.4506.5800", test_version2:"3.0.4506.5845") ||
     version_in_range(version:dllv3, test_version:"3.0.4506.5000", test_version2:"3.0.4506.5006")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
