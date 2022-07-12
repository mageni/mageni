###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Hyper-V Multiple Vulnerabilities (KB3211308)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810848");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0163", "CVE-2017-0168", "CVE-2017-0180");
  script_bugtraq_id(97465, 97418, 97444);
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-04-12 12:24:16 +0530 (Wed, 12 Apr 2017)");
  script_name("Microsoft Windows Hyper-V Multiple Vulnerabilities (KB3211308)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3211308.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when the Windows Hyper-V
  Network Switch on a host operating system fails to properly validate input from
  an authenticated user on a guest operating system.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to information on the Hyper-V host operating system.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3211308");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3211308/security-update-for-hyper-v-in-windows-server-2008");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

qzVer = fetch_file_version(sysPath:sysPath, file_name:"Hvax64.exe");
if(!qzVer){
  exit(0);
}

if(hotfix_check_sp(win2008x64:3) > 0)
{
  if(version_is_less(version:qzVer, test_version:"6.0.6002.18688"))
  {
    Vulnerable_range = "Less than 6.0.6002.18688";
    VULN = TRUE ;
  }

  else if(version_in_range(version:qzVer, test_version:"6.6.6002.24000", test_version2:"6.0.6002.24070"))
  {
    Vulnerable_range = "6.6.6002.24000 - 6.0.6002.24070";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\Hvax64.exe" + '\n' +
           'File version:     ' + qzVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
