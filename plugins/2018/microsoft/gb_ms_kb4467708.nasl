###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4467708)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814180");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8562", "CVE-2018-8564", "CVE-2018-8256", "CVE-2018-8407",
                "CVE-2018-8415", "CVE-2018-8417", "CVE-2018-8454", "CVE-2018-8471",
                "CVE-2018-8476", "CVE-2018-8485", "CVE-2018-8541", "CVE-2018-8542",
                "CVE-2018-8543", "CVE-2018-8544", "CVE-2018-8545", "CVE-2018-8547",
                "CVE-2018-8549", "CVE-2018-8550", "CVE-2018-8551", "CVE-2018-8552",
                "CVE-2018-8554", "CVE-2018-8555", "CVE-2018-8556", "CVE-2018-8557",
                "CVE-2018-8561", "CVE-2018-8567", "CVE-2018-8584", "CVE-2018-8588",
                "CVE-2018-8592");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-14 17:32:14 +0530 (Wed, 14 Nov 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4467708)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4467708.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists,

  - in the way that Microsoft Edge handles cross-origin requests.

  - in Windows when the Win32k component fails to properly handle objects in
    memory.

  - when an open source customization for Microsoft Active Directory Federation
    Services (AD FS) does not properly sanitize a specially crafted web request to
    an affected AD FS server.

  - in the way that the Chakra scripting engine handles objects in memory in
    Microsoft Edge.

  - A security feature bypass exists when Windows incorrectly validates kernel
    driver signatures.

  - when DirectX improperly handles objects in memory.

  - when Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - when VBScript improperly discloses the contents of its memory, which could
    provide an attacker with information to further compromise the user's computer
    or data.

  - when Microsoft Edge improperly handles specific HTML content.

  - in Microsoft JScript that could allow an attacker to bypass Device Guard.

  - in PowerShell that could allow an attacker to execute unlogged code.

  - when PowerShell improperly handles specially crafted files.

  - in the way that Windows Deployment Services TFTP Server handles objects in
    memory.

  - in the way that the Microsoft RemoteFX Virtual GPU miniport driver handles
    objects in memory.

  - An elevation of privilege exists in Windows COM Aggregate Marshaler.

  - when Windows Audio Service fails to properly handle objects in memory.

  - when Microsoft Edge does not properly enforce cross-domain policies, which
    could allow an attacker to access information from one domain and inject it
    into another domain.

  - in the way that the VBScript engine handles objects in memory.

  - in Windows 10 version 1809 when installed from physical media (USB, DVD, etc.

  - when Kernel Remote Procedure Call Provider driver improperly
    initializes objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code, bypass security restrictions and load improperly signed
  drivers into the kernel, gain the same user rights as the current user, obtain
  information to further compromise the user's system, improperly discloses file
  information, trick a user into believing that the user was on a legitimate website
  and escalate privileges.");

  script_tag(name:"affected", value:"Windows 10 Version 1809 for 32-bit Systems,

  Windows 10 Version 1809 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4467708");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.17763.0", test_version2:"11.0.17763.133"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.17763.0 - 11.0.17763.133");
  security_message(data:report);
  exit(0);
}
exit(99);
