###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4015219)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810922");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0202", "CVE-2017-0203", "CVE-2017-0205", "CVE-2017-0208",
                "CVE-2017-0210", "CVE-2017-0211", "CVE-2017-0192", "CVE-2017-0191",
                "CVE-2017-0189", "CVE-2017-0188", "CVE-2017-0186", "CVE-2017-0185",
                "CVE-2017-0184", "CVE-2017-0185", "CVE-2017-0184", "CVE-2017-0183",
                "CVE-2017-0182", "CVE-2017-0181", "CVE-2017-0180", "CVE-2017-0179",
                "CVE-2017-0178", "CVE-2017-0167", "CVE-2017-0166", "CVE-2017-0165",
                "CVE-2017-0163", "CVE-2017-0162", "CVE-2017-0160", "CVE-2017-0158",
                "CVE-2017-0156", "CVE-2017-0093", "CVE-2017-0058", "CVE-2013-6629");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-04-12 10:47:16 +0530 (Wed, 12 Apr 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4015219)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft security update KB4015219.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The open-source libjpeg image-processing library fails to properly handle
    objects in memory.

  - The win32k component improperly provides kernel information.

  - An error in the way that the Scripting Engine renders when handling objects
    in memory in Microsoft browsers.

  - The VBScript engine, when rendered in Internet Explorer, improperly handles
    objects in memory.

  - Microsoft Graphics Component fails to properly handle objects in memory.

  - Microsoft .NET Framework fails to properly validate input before loading
    libraries.

  - Windows Hyper-V Network Switch on a host server fails to properly validate
    input from an authenticated user on a guest operating system.

  - Windows fails to properly sanitize handles in memory.

  - LDAP request buffer lengths are improperly calculated.

  - Windows kernel improperly handles objects in memory.

  - Windows kernel-mode driver fails to properly handle objects in memory.

  - Adobe Type Manager Font Driver (ATMFD.dll) fails to properly handle objects
    in memory.

  - Edge Content Security Policy (CSP) fails to properly validate certain
    specially crafted documents.

  - Chakra scripting engine does not properly handle objects in memory.

  - Internet Explorer does not properly enforce cross-domain policies.

  - Microsoft Windows OLE fails an integrity-level check");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system, execute arbitrary
  code in the context of the current user, gain the same user rights as the current
  user, could take control of an affected system and cause a host machine to crash.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-gb/help/4015219");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.872"))
  {
    report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
             'File version:     ' + edgeVer  + '\n' +
             'Vulnerable range: 11.0.10586.0 - 11.0.10586.872\n' ;
    security_message(data:report);
    exit(0);
  }
}
