###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Task Scheduler Privilege Escalation Vulnerability (2988948)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804902");
  script_version("2019-05-16T07:59:11+0000");
  script_cve_id("CVE-2014-4074");
  script_bugtraq_id(69593);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-16 07:59:11 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2014-09-10 12:15:20 +0530 (Wed, 10 Sep 2014)");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft Windows Task Scheduler Privilege Escalation Vulnerability (2988948)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-054.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists because Windows Task
  Scheduler improperly conducts integrity checks on tasks.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  local users to gain escalated privileges.");

  script_tag(name:"affected", value:"Windows 8 x32/x64 Edition,
  Windows 8.1 x32/x64 Edition,
  Windows Server 2012,
  Windows Server 2012 R2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60983");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-054");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Schedsvc.dll");
if(!win32SysVer){
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_in_range(version:win32SysVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.17067") ||
     version_in_range(version:win32SysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21187")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and Win 2012 R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"6.3.9600.17276")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
