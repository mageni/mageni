###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows PDF Library Memory Corruption Vulnerability (4010319)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810622");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0023");
  script_bugtraq_id(96075);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-15 08:29:25 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows PDF Library Memory Corruption Vulnerability (4010319)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS17-009");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as Microsoft Windows PDF
  Library improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to corrupt memory in a way that enables an attacker to execute arbitrary code
  in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 x32/x64

  Microsoft Windows 10 Version 1511 x32/x64

  Microsoft Windows 10 Version 1607 x32/x64

  Microsoft Windows Server 2016 x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4010319");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-009");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012:1, win2012R2:1, win10:1,
                   win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

pdfVer = fetch_file_version(sysPath:sysPath, file_name:"windows.data.pdf.dll");
pdfVer1 = fetch_file_version(sysPath:sysPath, file_name:"win32k.sys");
edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!pdfVer && !pdfVer1 && !edgeVer){
  exit(0);
}

if( pdfVer && (hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0))
{
  if(version_is_less(version:pdfVer, test_version:"6.3.9600.18569"))
  {
    Vulnerable_range = "Less than 6.3.9600.18569";
    VULN = TRUE ;
  }
}

## Taking 'Win32k.sys' file as KB includes all files related to all bulletins in one patch
## Specific pdf library file not available
else if( pdfVer1 && (hotfix_check_sp(win2012:1) > 0))
{
  if(version_is_less(version:pdfVer1, test_version:"6.2.9200.22097"))
  {
    Vulnerable_range = "Less than 6.2.9200.22097";
    VULN2 = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0 && edgeVer)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17319"))
  {
    Vulnerable_range = "Less than 11.0.10240.17319";
    VULN3 = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.838"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.839";
    VULN3 = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.952"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.952";
    VULN3 = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\windows.data.pdf.dll" + '\n' +
           'File version:     ' + pdfVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
           'File version:     ' + pdfVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN3)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
