###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows PDF Library Multiple Information Disclosure Vulnerabilities (3188733)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809310");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3370", "CVE-2016-3374");
  script_bugtraq_id(92839, 92838);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-14 08:36:03 +0530 (Wed, 14 Sep 2016)");
  script_name("Microsoft Windows PDF Library Multiple Information Disclosure Vulnerabilities (3188733)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-115");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to Windows PDF Library
  improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to could obtain information to further compromise a target system.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3188733");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms16-115");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-115");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"System32\Glcndfilter.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"System32\Windows.data.pdf.dll");
if(!dllVer1 && !dllVer2){
  exit(0);
}

if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:dllVer1, test_version:"6.2.9200.21954"))
  {
     Vulnerable_range = "Less than 6.2.9200.21954";
     VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer1, test_version:"6.3.9600.18454"))
  {
    Vulnerable_range = "Less than 6.3.9600.18454";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"10.0.10240.17113"))
  {
    Vulnerable_range = "Less than 10.0.10240.17113";
    VULN2 = TRUE ;
  }
  else if(version_in_range(version:dllVer2, test_version:"10.0.10586.0", test_version2:"10.0.10586.588"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.588";
    VULN2 = TRUE ;
  }
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\system32\windows.data.pdf.dll"+ '\n' +
           'File version:     ' + dllVer2  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\system32\Glcndfilter.dll" + '\n' +
           'File version:     ' + dllVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
