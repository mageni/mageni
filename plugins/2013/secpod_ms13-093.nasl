###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-093.nasl 32358 2013-11-11 09:00:42Z nov$
#
# MS Windows Ancillary Function Driver Information Disclosure Vulnerability (2875783)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.903501");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-3887");
  script_bugtraq_id(63545);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-11-13 09:16:37 +0530 (Wed, 13 Nov 2013)");
  script_name("MS Windows Ancillary Function Driver Information Disclosure Vulnerability (2875783)");


  script_tag(name:"summary", value:"This host is missing an important security update according to
Microsoft Bulletin MS13-093");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"The flaw is due an error in Ancillary Function Driver (AFD) which does not
properly copies data from kernel memory to user memory.");
  script_tag(name:"affected", value:"Microsoft Windows Server 2012
Microsoft Windows XP x64 Edition Service Pack 2 and prior
Microsoft Windows 7 x64 Edition Service Pack 1 and prior
Microsoft Windows 2003 x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");
  script_tag(name:"impact", value:"Successful exploitation will allow disclosure of potentially sensitive
information if an attacker logs on to a user's system and runs a specially
crafted application.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55558");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2875783");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-093");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
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

if(hotfix_check_sp(xpx64:3, win2003x64:3, win7x64:2, win2008r2:2, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

afdSysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Drivers\afd.sys");
if(!afdSysVer){
  exit(0);
}

if(hotfix_check_sp(xpx64:3, win2003x64:3) > 0)
{
  if(version_is_less(version:afdSysVer, test_version:"5.2.3790.5217")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:afdSysVer, test_version:"6.1.7601.18272") ||
    version_in_range(version:afdSysVer, test_version:"6.2.9200.22000", test_version2:"6.1.7601.22466")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:afdSysVer, test_version:"6.2.9200.16706") ||
     version_in_range(version:afdSysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20813")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
