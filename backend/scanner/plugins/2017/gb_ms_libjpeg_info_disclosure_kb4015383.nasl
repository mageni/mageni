###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows 'libjpeg' Information Disclosure Vulnerability (KB4015383)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810928");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2013-6629");
  script_bugtraq_id(63676);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-04-12 10:47:16 +0530 (Wed, 12 Apr 2017)");
  script_name("Microsoft Windows 'libjpeg' Information Disclosure Vulnerability (KB4015383)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security update KB4015383");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists within the open-source
  libjpeg image-processing library where it fails to properly handle objects
  in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to retrieve information that could lead to an Address Space Layout Randomization
  (ASLR) bypass. And that could allow for bypassing the ASLR security feature that
  protects users from a broad class of vulnerabilities.");

  script_tag(name:"affected", value:"Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-gb/help/4015383");

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

if(hotfix_check_sp(winVista:3, win2008:3, winVistax64:3, win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

if(!asVer = fetch_file_version(sysPath:sysPath, file_name:"Gdiplus.dll")){
  exit(0);
}

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:asVer, test_version:"5.2.6002.19749"))
  {
    Vulnerable_range = "Less than 5.2.6002.19749";
    VULN = TRUE ;
  }

  else if(version_in_range(version:asVer, test_version:"5.2.6002.24000", test_version2:"5.2.6002.24071"))
  {
    Vulnerable_range = "5.2.6002.24000 - 5.2.6002.24071";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\Gdiplus.dll" + '\n' +
           'File version:     ' + asVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
