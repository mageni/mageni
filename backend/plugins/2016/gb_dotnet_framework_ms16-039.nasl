###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnet_framework_ms16-039.nasl 0057419 2016-03-10 09:15:08Z mar$
#
# Microsoft .NET Framework Remote Code Execution Vulnerability (3148522)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807663");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2016-0145");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-04-13 13:08:50 +0530 (Wed, 13 Apr 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (3148522)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-039");

  script_tag(name:"vuldetect", value:"Gets the vulnerable file version and
  checks if the appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of specially
  crafted embedded fonts in the windows font library.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to install programs, view, change, or delete data, or create new
  accounts with full user rights.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.0 SP2

  Microsoft .NET Framework 3.5 and 3.5.1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3142042");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3142043");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3142041");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3142045");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-039");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win2012:1, win8_1:1, win8_1x64:1,
  win2012R2:1, winVista:3, win2008:3) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET";
if(!registry_key_exists(key:key)){
  exit(0);
}

key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0";
if(!registry_key_exists(key:key)){
  exit(0);
}

path = registry_get_sz(key:key , item:"All Assemblies In");
if(path){
  dllVer = fetch_file_version(sysPath:path, file_name:"System.printing.dll");
}

if(dllVer)
{
  ## MS16-039: Description of the security update for the .NET Framework 3.5 in Windows 8.1 and Windows Server 2012 R2: April 12, 2016
  ## MS16-039: Description of the security update for the .NET Framework 3.5 in Windows Server 2012: April 12, 2016
  ## MS16-039: Description of the security update for the .NET Framework 3.5.1 in Windows 7
  ## Service Pack 1 and Windows Server 2008 R2 Service Pack 1: April 12, 2016
  if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win2012:1, win8_1:1, win8_1x64:1, win2012R2:1) > 0)
  {
    if(version_in_range(version:dllVer, test_version:"3.0.6920.8700", test_version2:"3.0.6920.8711"))
    {
      VULN = TRUE ;
      vulnerable_range = "3.0.6920.8700 - 3.0.6920.8711";
    }
  }
  ##MS16-039: Description of the security update for the .NET Framework 3.0 Service Pack 2
  ## in Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2: April 12, 2016
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_in_range(version:dllVer, test_version:"3.0.6920.4000", test_version2:"3.0.6920.4234"))
    {
      VULN = TRUE ;
      vulnerable_range = "3.0.6920.4000 - 3.0.6920.4234";
    }

    else if(version_in_range(version:dllVer, test_version:"3.0.6920.8000", test_version2:"3.0.6920.8711"))
    {
      VULN = TRUE ;
      vulnerable_range = "3.0.6920.8000 - 3.0.6920.8711";
    }
  }
}

if(VULN)
{
  report = 'File checked:     ' + path + "System.printing.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + vulnerable_range + '\n' ;
  security_message(data:report);
}
