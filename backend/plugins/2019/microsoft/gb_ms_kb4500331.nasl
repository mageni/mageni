# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814894");
  script_version("2019-05-22T07:03:13+0000");
  script_cve_id("CVE-2019-0708");
  script_bugtraq_id(108273);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-22 07:03:13 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-17 15:27:29 +0530 (Fri, 17 May 2019)");
  script_name("Microsoft Windows Remote Desktop Service Remote Code Execution Vulnerability (KB4500331)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4500331.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when an unauthenticated attacker
  connects to the system using RDP and sends specially crafted requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  execute arbitrary code on the target system.");

  script_tag(name:"affected", value:"Microsoft Windows XP SP3
  Microsoft Windows Server 2003 SP2
  Microsoft Windows XP Professional x64 Edition SP2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-in/help/4500331/windows-update-kb4500331");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");


sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"\drivers\Termdd.sys");
if(!fileVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:fileVer , test_version:"5.1.2600.7701"))
  {
    report = report_fixed_ver(file_checked:sysPath + "\drivers\Termdd.sys",
                              file_version:fileVer, vulnerable_range:"Less than 5.1.2600.7701");
    security_message(data:report);
    exit(0);
  }
}

else if(hotfix_check_sp(win2003:3, win2003x64:3, xpx64:3) > 0){

  if(version_is_less(version:fileVer , test_version:"5.2.3790.6787"))
  {
    report = report_fixed_ver(file_checked:sysPath + "\drivers\Termdd.sys",
                              file_version:fileVer, vulnerable_range:"Less than 5.2.3790.6787");
    security_message(data:report);
    exit(0);
  }
}
exit(99);
