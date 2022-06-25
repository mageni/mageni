###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Remote Code Execution Vulnerabilities (3104503)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806647");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-6108");
  script_bugtraq_id(78499);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-12-09 13:05:49 +0530 (Wed, 09 Dec 2015)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerabilities (3104503)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-128.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to an error in
  Windows font library which improperly handles specially crafted embedded
  fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.0 Service Pack 2
  Microsoft .NET Framework 3.5
  Microsoft .NET Framework 3.5.1
  Microsoft .NET Framework 4
  Microsoft .NET Framework 4.5, 4.5.1, and 4.5.2,
  Microsoft .NET Framework 4.6");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3104503");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3099874");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3099869");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3099866");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3099862");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3099864");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3099863");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3099860");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-128");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3,
   win2008r2:2, win8:1, win8x64:1, win8_1:1, win8_1x64:1, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

##.NET Framework 3.5
key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0";
if(registry_key_exists(key:key))
{
  pathPrint = registry_get_sz(key:key, item:"All Assemblies In");
  if(pathPrint){
    dllVer = fetch_file_version(sysPath:pathPrint, file_name:"System.printing.dll");
  }
  ## on Windows 8 and Windows Server 2012
  if(dllVer)
  {
    if(hotfix_check_sp(win8:1, win2012:1) > 0)
    {
      if(version_in_range(version:dllVer, test_version:"3.0.6920.6400", test_version2:"3.0.6920.6421"))
      {
        VULN1 = TRUE ;
        vulnerable_range1 = "3.0.6920.6400 - 3.0.6920.6421";
      }

      else if(version_in_range(version:dllVer, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8692"))
      {
        VULN1 = TRUE ;
        vulnerable_range1 = "3.0.6920.8600 - 3.0.6920.8692";
      }
    }

    ## Description of the security update for the .NET Framework 3.5.1 on
    else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
    {
      if(version_in_range(version:dllVer, test_version:"3.0.6920.5400", test_version2:"3.0.6920.5469"))
      {
        VULN1 = TRUE ;
        vulnerable_range1 = "3.0.6920.5400 - 3.0.6920.5469";
      }
      else if(version_in_range(version:dllVer, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8692"))
      {
        VULN1 = TRUE ;
        vulnerable_range1 = "3.0.6920.8600 - 3.0.6920.8692";
      }
    }
  }
}

##Description of the security update for the .NET Framework 3.0
##Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008
## Service Pack 2

sysPath = smb_get_systemroot();
if(sysPath)
{
  ## .NET Framework 3.0 Service Pack 2
  key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0";
  if(registry_key_exists(key:key))
  {
    exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\XPSViewer\XPSViewer.exe");
    if(exeVer)
    {
      ## .NET Framework 3.0 Service Pack 2 on Windows Vista and Windows Server 2008
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:exeVer, test_version:"3.0.6920.4200", test_version2:"3.0.6920.4229"))
        {
          VULN2 = TRUE ;
          vulnerable_range2 = "3.0.6920.4200 - 3.0.6920.4229";
        }
        else if(version_in_range(version:exeVer, test_version:"3.0.6920.7000", test_version2:"3.0.6920.8692"))
        {
          VULN2 = TRUE ;
          vulnerable_range2 = "3.0.6920.7000 - 3.0.6920.8692";
        }
      }
    }
  }
}

## Description of the security update for the .NET Framework 4
## on Windows Vista and Windows Server 2008
key = "SOFTWARE\Microsoft\ASP.NET\4.0.30319.0";
if(registry_key_exists(key:key))
{
  pathPres = registry_get_sz(key:key, item:"Path");
  if(pathPres)
  {
    dllPres = fetch_file_version(sysPath:pathPres, file_name:"WPF\Presentationcore.dll");
    if(dllPres)
    {
      ## .NET Framework 4 on Windows Vista, Windows Server 2008
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllPres, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1043"))
        {
          VULN3 = TRUE ;
          vulnerable_range3 = "4.0.30319.1000 - 4.0.30319.1043";
        }
        else if(version_in_range(version:dllPres, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2076"))
        {
          VULN3 = TRUE ;
          vulnerable_range3 = "4.0.30319.2000 - 4.0.30319.2076";
        }
      }
    }
  }
}

## Service Pack 2 and Windows Server 2008 Service Pack 2
key = "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client\";
if(registry_key_exists(key:key))
{
  pathv45 = registry_get_sz(key:key, item:"InstallPath");
  if(pathv45)
  {
    dllv45 = fetch_file_version(sysPath:pathv45, file_name:"WPF\wpftxt_v0400.dll");
    if(dllv45)
    {
      ## .NET Framework 4.5/4.5.1/4.5.2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllv45, test_version: "4.0", test_version2:"4.0.30319.34279"))
        {
          VULN4 = TRUE ;
          vulnerable_range4 = "4.0 - 4.0.30319.34279";
        }
        else if(version_in_range(version:dllv45, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36329"))
        {
          VULN4 = TRUE ;
          vulnerable_range4 = "4.0.30319.36000 - 4.0.30319.36329";
        }

      ## .NET Framework 4.6 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if(version_in_range(version:dllv45, test_version: "4.6", test_version2:"4.6.117"))
        {
          VULN4 = TRUE ;
          vulnerable_range4 = "4.6 - 4.6.117";
        }
      }
    }
  }
}

## .NET Framework 3.5 on Windows 8.1 and Windows Server 2012R2
key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0";
if(registry_key_exists(key:key))
{
  pathAss = registry_get_sz(key:key, item:"All Assemblies In");
  if(pathAss)
  {
    dllPres2 = fetch_file_version(sysPath:pathAss, file_name:"presentationcore.dll");
    if(dllPres2)
    {
      if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
      {
        if(version_in_range(version:dllPres2, test_version:"3.0.6920.7000", test_version2:"3.0.6920.8008"))
        {
          VULN5 = TRUE ;
          vulnerable_range5 = "3.0.6920.7000 - 3.0.6920.8008";
        }
        else if(version_in_range(version:dllVer, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8692"))
        {
          VULN5 = TRUE ;
          vulnerable_range5 = "3.0.6920.8600 - 3.0.6920.8692";
        }
      }
    }
  }
}


if(VULN1)
{
  report = 'File checked:     ' + pathPrint + "\System.printing.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\system32\XPSViewer\XPSViewer.exe" + '\n' +
           'File version:     ' + exeVer + '\n' +
           'Vulnerable range: ' + vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN3)
{
  report = 'File checked:     ' + pathPres + "\WPF\Presentationcore.dll" + '\n' +
           'File version:     ' + dllPres + '\n' +
           'Vulnerable range: ' + vulnerable_range3 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN4)
{
  report = 'File checked:     ' + pathv45 + "\WPF\wpftxt_v0400.dll" + '\n' +
           'File version:     ' + dllv45 + '\n' +
           'Vulnerable range: ' + vulnerable_range4 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN5)
{
  report = 'File checked:     ' + pathAss + "\presentationcore.dll" + '\n' +
           'File version:     ' + dllPres2 + '\n' +
           'Vulnerable range: ' + vulnerable_range5 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
