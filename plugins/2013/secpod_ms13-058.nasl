###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Defender Privilege Elevation Vulnerability (2847927)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902979");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2013-3154");
  script_bugtraq_id(60981);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2013-07-10 10:05:39 +0530 (Wed, 10 Jul 2013)");
  script_name("Microsoft Windows Defender Privilege Elevation Vulnerability (2847927)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54063/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2847927");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-058");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the security context of the LocalSystem account.");

  script_tag(name:"affected", value:"Windows Defender for

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error within Windows Defender related to
  pathnames and can be exploited to execute arbitrary code with system privileges.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-058.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2)<=0){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows Defender";
if(!registry_key_exists(key:key)){
  exit(0);
}

program_files_path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                     item:"ProgramFilesDir");
if(!program_files_path){
  exit(0);
}

defender_ver = fetch_file_version(sysPath:program_files_path,
                 file_name:"Windows Defender\Mpclient.dll");
if(!defender_ver){
  exit(0);
}

if(version_is_less(version:defender_ver, test_version:"6.1.7600.17316") ||
   version_in_range(version:defender_ver, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21530")||
   version_in_range(version:defender_ver, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18169")||
   version_in_range(version:defender_ver, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22340"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
