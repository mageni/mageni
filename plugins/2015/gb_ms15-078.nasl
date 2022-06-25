###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-078.nasl 2015-07-21 11:36:10 +0530 Jul$
#
# Microsoft Font Driver Remote Code Execution Vulnerability (3079904)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805726");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-2426");
  script_bugtraq_id(75951);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-07-21 11:36:10 +0530 (Tue, 21 Jul 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Font Driver Remote Code Execution Vulnerability (3079904)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-078.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the Windows Adobe Type
  Manager Library improperly handles specially crafted OpenType fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code. Failed exploit attempts will result in
  a denial-of-service condition.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64

  Microsoft Windows 10 x32/x64

  Microsoft Windows Server 2012/R2

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3079904");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-078");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

userVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Atmfd.dll");
if(!userVer){
  exit(0);
}
## Win 8.1 and win2012R2
if(hotfix_check_sp(winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2, win8:1,
   win8x64:1, win2012:1, win8_1:1, win8_1x64:1, win2012R2:1, win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:userVer, test_version:"5.1.2.243"))
  {
    report = 'File checked:     ' + sysPath + "\system32\Atmfd.dll" + '\n' +
             'File version:     ' + userVer  + '\n' +
             'Vulnerable range: Less than 5.1.2.243\n' ;
    security_message(data:report);
    exit(0);
  }
}
