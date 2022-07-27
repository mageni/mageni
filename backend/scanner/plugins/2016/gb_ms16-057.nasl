###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows Shell Remote Code Execution Vulnerability (3156987)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807586");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0179");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-05-11 08:26:35 +0530 (Wed, 11 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS Windows Shell Remote Code Execution Vulnerability (3156987)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-057.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists when windows Shell
  improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application
  and failed attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64
  Microsoft Windows Server 2012 R2
  Microsoft Windows 10 x32/x64
  Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3156987");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-057");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win10:1, win10x64:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

shelldllPath = smb_get_systemroot();
if(!shelldllPath){
  exit(0);
}

shelldllVer = fetch_file_version(sysPath:shelldllPath, file_name:"system32\Windows.ui.dll");
if(!shelldllVer){
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:shelldllVer, test_version:"6.3.9600.18302"))
  {
    Vulnerable_range = "Less than 6.3.9600.18302";
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:shelldllVer, test_version:"10.0.10240.16841"))
  {
    Vulnerable_range = "Less than 10.0.10240.16841";
    VULN = TRUE;
  }
  else if(version_in_range(version:shelldllVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.305"))
  {
    VULN = TRUE;
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.305";
  }
}

if(VULN)
{
  report = 'File checked:     ' + shelldllPath + "\System32\Windows.ui.dll" + '\n' +
           'File version:     ' + shelldllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
}
