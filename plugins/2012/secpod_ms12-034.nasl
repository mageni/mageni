###############################################################################
# OpenVAS Vulnerability Test
#
# MS Security Update For Microsoft Office, .NET Framework, and Silverlight (2681578)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902832");
  script_version("2019-05-03T12:31:27+0000");
  script_bugtraq_id(50462, 53324, 53326, 53327, 53335, 53347, 53351, 53358,
                    53360, 53363);
  script_cve_id("CVE-2011-3402", "CVE-2012-0159", "CVE-2012-0162", "CVE-2012-0164",
                "CVE-2012-0165", "CVE-2012-0167", "CVE-2012-0176", "CVE-2012-0180",
                "CVE-2012-0181", "CVE-2012-1848");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-05-09 09:09:09 +0530 (Wed, 09 May 2012)");
  script_name("MS Security Update For Microsoft Office, .NET Framework, and Silverlight (2681578)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49120");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49121");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2681578");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027048");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-034");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_silverlight_detect.nasl",
                      "secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain escalated privileges
  and execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 4

  Microsoft Silverlight 4 and 5

  Microsoft .NET Framework 3.5.1

  Microsoft Office 2003 Service Pack 3

  Microsoft Office 2007 Service Pack 2

  Microsoft Office 2010 Service Pack 1

  Microsoft .NET Framework 3.0 Service Pack 2

  Microsoft Windows 7 Service Pack 1 and prior

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows 2003 Service Pack 2 and prior

  Microsoft Windows Vista Service Pack 2 and prior

  Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - An error exists when parsing TrueType fonts.

  - An error in the t2embed.dll module when parsing TrueType fonts can be
    exploited via a specially crafted TTF file.

  - An error in GDI+ when handling certain records can be exploited via a
    specially crafted EMF image file.

  - An error in win32k.sys related to certain Windows and Messages handling
    can be exploited to execute arbitrary code in the context of another
    process.

  - An error in win32k.sys when handling keyboard layout files can be exploited
    to execute arbitrary code in the context of another process.

  - An error in win32k.sys related to scrollbar calculations can be exploited
    to execute arbitrary code in the context of another process.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-034.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

if( infos = get_app_version_and_location( cpe:"cpe:/a:microsoft:silverlight", exit_no_version:FALSE ) ) {
  mslVers = infos['version'];
  mslPath = infos['location'];

  if( mslVers ) {
    if( version_is_less( version:mslVers, test_version:"4.1.10329" ) ||
        version_in_range( version:mslVers, test_version:"5.0", test_version2:"5.1.10410" ) ) {
      report = report_fixed_ver( installed_version:mslVers, vulnerable_range:"< 4.1.10329 and 5.0 - 5.1.10410", install_path:mslPath );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
}

key = "SOFTWARE\Microsoft\ASP.NET\4.0.30319.0";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"Path");
  if(path){
    dllv4 = fetch_file_version(sysPath:path, file_name:"WPF\Presentationcore.dll");
  }
}

## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7
if(dllv4 &&
  (version_in_range(version:dllv4, test_version:"4.0.30319.000", test_version2:"4.0.30319.274") ||
   version_in_range(version:dllv4, test_version:"4.0.30319.500", test_version2:"4.0.30319.549")))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"All Assemblies In");
  if(path){
    dllv3 = fetch_file_version(sysPath:path, file_name:"System.Printing.dll");
  }
}

## .NET Framework 3.0 Service Pack 2 on Windows XP and Windows Server 2003
if(dllv3 && (hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.0.6920.4000", test_version2:"3.0.6920.4020") ||
     version_in_range(version:dllv3, test_version:"3.0.6920.5000", test_version2:"3.0.6920.5809"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 3.0 Service Pack 2 on Windows Vista and Windows Server 2008
if(dllv3 && (hotfix_check_sp(winVista:3, win2008:3) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.0.6920.4000", test_version2:"3.0.6920.4212") ||
     version_in_range(version:dllv3, test_version:"3.0.6920.5000", test_version2:"3.0.6920.5793"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
if(dllv3 && (hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.0.6920.4000", test_version2:"3.0.6920.5004") ||
     version_in_range(version:dllv3, test_version:"3.0.6920.5800", test_version2:"3.0.6920.5808") ||
     version_in_range(version:dllv3, test_version:"3.0.6920.5400", test_version2:"3.0.6920.5447") ||
     version_in_range(version:dllv3, test_version:"3.0.6920.5700", test_version2:"3.0.6920.5793"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007, 2010
if(officeVer && officeVer =~ "^1[24]\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(path)
  {
    foreach ver (make_list("OFFICE12", "OFFICE14"))
    {
      offPath = path + "\Microsoft Shared\" + ver;
      dllVer = fetch_file_version(sysPath:offPath, file_name:"Ogl.dll");

      if(dllVer &&
        (version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6117.5000") ||
         version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6659.4999")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

## MS Office 2003
if(officeVer && officeVer =~ "^11\.")
{
  offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
  if(offPath)
  {
    offPath = offPath + "\Microsoft Office\OFFICE11";
    dllVer = fetch_file_version(sysPath:offPath, file_name:"Gdiplus.dll");

    if(dllVer && version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8344"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
if(sysVer)
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.6206"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4980"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18607") ||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22830"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:sysVer, test_version:"6.1.7600.16988") ||
       version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21178")||
       version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17802")||
       version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21954"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Dwrite.dll");
if(dllVer)
{
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"7.0.6002.18592") ||
       version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22806"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
     if(version_is_less(version:dllVer, test_version:"6.1.7600.16972") ||
       version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21161")||
       version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17788")||
       version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21934"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
  }
}

exit(99);