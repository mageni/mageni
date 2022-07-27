###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows Shell and Tablet Input Band Remote Code Execution Vulnerabilities (3096443)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806090");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-2515", "CVE-2015-2548");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-10-14 08:11:18 +0530 (Wed, 14 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS Windows Shell and Tablet Input Band Remote Code Execution Vulnerabilities (3096443)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-109.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Windows Shell fails to properly handle objects in memory.

  - Tablet Input Band fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to conduct denial-of-service conditions and execute arbitrary code
  in the context of the currently logged-in user.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012

  Microsoft Windows 10 x32/x64

  Microsoft Windows Server 2012R2

  Microsoft Windows 8/8.1 x32/x64

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3096443");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-109");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008:3, win2008r2:2, win8:1, win8x64:1,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, winVista:3, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"system32\Shell32.dll");

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
if(path){
  path += "\microsoft shared\ink";
  dllVer2 = fetch_file_version(sysPath:path, file_name:"TipBand.dll");
}

if(!dllVer1 && !dllVer2){
  exit(0);
}

## Currently not supporting for Windows Server 2008 64 bit
if(hotfix_check_sp(win2008:3, winVista:3) > 0 && dllVer1)
{
  if(version_is_less(version:dllVer1, test_version:"6.0.6002.19459"))
  {
    Vulnerable_range = "Version Less than - 6.0.6002.19459";
    dllVer = dllVer1 ;
    location = sysPath + "\system32\Shell32.dll";
    VULN = TRUE ;
  }

  if(version_in_range(version:dllVer1, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23766"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23766";
    dllVer = dllVer1 ;
    location = sysPath + "\system32\Shell32.dll";
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(winVista:3) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"6.0.6002.19483"))
  {
    Vulnerable_range = "Version Less than - 6.0.6002.19483";
    dllVer = dllVer2 ;
    location = path + "\TipBand.dll";
    VULN = TRUE ;
  }

  if(version_in_range(version:dllVer2, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23792"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23792";
    dllVer = dllVer2 ;
    location = path + "\TipBand.dll";
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(win2008r2:2, win7:2, win7x64:2) > 0 && dllVer1)
{
  if(version_is_less(version:dllVer1, test_version:"6.1.7601.18952"))
  {
    Vulnerable_range = "Version Less than - 6.1.7601.18952";
    dllVer = dllVer1 ;
    location = sysPath + "\system32\Shell32.dll";
    VULN = TRUE;

  }
  if(version_in_range(version:dllVer1, test_version:"6.1.7601.23000", test_version2:"6.1.7601.23154"))
  {
    Vulnerable_range = "6.1.7601.23000 - 6.1.7601.23154";
    dllVer = dllVer1 ;
    location = sysPath + "\system32\Shell32.dll";
    VULN = TRUE;
  }
}

if(hotfix_check_sp(win7:2, win7x64:2) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"6.1.7601.18984"))
  {
    Vulnerable_range = "Version Less than - 6.1.7601.18984";
    dllVer = dllVer2 ;
    location = path + "\TipBand.dll";
    VULN = TRUE;
  }
  if(version_in_range(version:dllVer2, test_version:"6.1.7601.23000", test_version2:"6.1.7601.23186"))
  {
    Vulnerable_range = "6.1.7601.23000 - 6.1.7601.23186";
    dllVer = dllVer2 ;
    location = path + "\TipBand.dll";
    VULN = TRUE;
  }
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0 && dllVer1)
{
  if(version_is_less(version:dllVer1, test_version:"6.2.9200.17464"))
  {
    Vulnerable_range = "Version Less than - 6.2.9200.17464";
    dllVer = dllVer1 ;
    location = sysPath + "\system32\Shell32.dll";
    VULN = TRUE;
  }
  if(version_in_range(version:dllVer1, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21577"))
  {
    Vulnerable_range = "6.2.9200.20000 - 6.2.9200.21577";
    dllVer = dllVer1 ;
    location = sysPath + "\system32\Shell32.dll";
    VULN = TRUE;
  }
}

## Win 8.1 Windows Server 2012 R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && dllVer1)
{
  if(version_is_less(version:dllVer1, test_version:"6.3.9600.18038")){
    Vulnerable_range = "Version Less than - 6.3.9600.18038";
    location = sysPath + "\system32\Shell32.dll";
    dllVer = dllVer1 ;
    VULN = TRUE;
  }
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer1)
{
  if(version_is_less(version:dllVer1, test_version:"10.0.10240.16542"))
  {
    Vulnerable_range = "Less than 10.0.10240.16542";
    location = sysPath + "\system32\Shell32.dll";
    dllVer = dllVer1 ;
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + location + "\n" +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
