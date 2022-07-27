###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4042007)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811862");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8717", "CVE-2017-8718");
  script_bugtraq_id(101161, 101162);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-10-11 10:25:48 +0530 (Wed, 11 Oct 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4042007)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4042007");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,
  multiple buffer overflow errors in the Microsoft JET Database Engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited this vulnerability to take control of
  an affected system. An attacker could then:

  - install programs

  - view, change, or delete data

  - create new accounts with full user rights.

  Users whose accounts are configured to have fewer user rights on the system could be less
  impacted than users who operate with administrative user rights.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4042007");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

if(fileVer = fetch_file_version(sysPath:sysPath, file_name:"SysWOW64\msexcl40.dll")){
  sysPath = sysPath + "\SysWOW64\msexcl40.dll";
}
else if(fileVer = fetch_file_version(sysPath:sysPath, file_name:"system32\msexcl40.dll")){
  sysPath = sysPath + "\system32\msexcl40.dll";
}

if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"4.0.9801.1"))
{
  report = 'File checked:     ' + sysPath + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: Less than 4.0.9801.1\n' ;
  security_message(data:report);
  exit(0);
}
