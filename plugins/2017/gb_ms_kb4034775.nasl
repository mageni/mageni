###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft JET Database Engine Remote Code Execution Vulnerability (KB4034775)
#
# Authors:
# Rinu <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811560");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0250");
  script_bugtraq_id(98100);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-08-09 09:37:46 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft JET Database Engine Remote Code Execution Vulnerability (KB4034775)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4034775");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a buffer overflow
  error in Microsoft JET Database Engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited this vulnerability to take complete
  control of an affected system.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4034775");
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

sysPath =  smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"SysWOW64\msexch40.dll");
fileVer1 = fetch_file_version(sysPath:sysPath, file_name:"system32\msexch40.dll");

if(!fileVer && !fileVer1){
  exit(0);
}

if(hotfix_check_sp(win2008:3) > 0 && version_is_less(version:fileVer1, test_version:"4.0.9752.0"))
{
  report = 'File checked:     ' + sysPath + "\system32\msexch40.dll" + '\n' +
           'File version:     ' + fileVer1  + '\n' +
           'Vulnerable range: Less than 4.0.9752.0\n' ;
  security_message(data:report);
  exit(0);
}

else if(hotfix_check_sp(win2008x64:3) > 0 && version_is_less(version:fileVer, test_version:"4.0.9752.0"))
{
  report = 'File checked:     ' + sysPath + "\SysWOW64\msexch40.dll" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: Less than 4.0.9752.0\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
