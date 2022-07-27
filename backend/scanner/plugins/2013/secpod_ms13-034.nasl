###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Antimalware Client Privilege Elevation Vulnerability (2823482)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901216");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2013-0078");
  script_bugtraq_id(58847);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2013-04-10 10:20:16 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft Antimalware Client Privilege Elevation Vulnerability (2823482)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52921");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2781197");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-034");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the security context of the LocalSystem account.");

  script_tag(name:"affected", value:"Windows Defender for Windows 8");

  script_tag(name:"insight", value:"Flaw is due to an unspecified error when improper pathnames are used
  by Windows Defender (Microsoft Antimalware Client).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-034.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8:1)<=0){
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
                				  file_name:"Windows Defender\MSASCui.exe");
if(!defender_ver){
  exit(0);
}

if(version_is_less(version:defender_ver, test_version:"4.2.223.0"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
