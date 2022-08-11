###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4034668)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811564");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0174", "CVE-2017-0250", "CVE-2017-0293", "CVE-2017-8591",
                "CVE-2017-8593", "CVE-2017-8620", "CVE-2017-8624", "CVE-2017-8625",
                "CVE-2017-8633", "CVE-2017-8635", "CVE-2017-8644", "CVE-2017-8652",
                "CVE-2017-8653", "CVE-2017-8655", "CVE-2017-8664", "CVE-2017-8666",
                "CVE-2017-8669", "CVE-2017-8672", "CVE-2017-8636", "CVE-2017-8640",
                "CVE-2017-8641");
  script_bugtraq_id(100038, 98100, 100039, 99430, 100032, 100034, 100061, 100063,
                    100069, 100055, 100056, 100051, 100057, 100044, 100047, 100059,
                    100027, 100085, 100089, 100068, 100072);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-08-09 12:09:14 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4034668)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4034668");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - The Win32k component fails to properly handle objects in
     memory.

  - Windows Input Method Editor (IME) when IME improperly handles parameters in
    a method of a DCOM class.

  - The way that Microsoft browser JavaScript engines render content when
    handling objects in memory.

  - Microsoft browsers improperly access objects in memory.

  - An error in Windows Error Reporting (WER).

  - The way JavaScript engines render when handling objects in memory in
    Microsoft browsers.

  - Windows Hyper-V on a host server fails to properly validate input from an
    authenticated user on a guest operating system.

  - The Microsoft JET Database Engine that could allow remote code execution on
    an affected system.

  - Windows Search improperly handles objects in memory.

  - Internet Explorer fails to validate User Mode Code Integrity (UMCI)
    policies.

  - Microsoft Edge improperly handles objects in memory.

  - Microsoft Windows PDF Library improperly handles objects in memory.

  - Microsoft Windows improperly handles NetBIOS packets.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited this vulnerability to run arbitrary
  code in kernel mode, instantiate the DCOM class and exploit the system even if IME
  is not enabled, gain access to sensitive information and system functionality and
  cause denial of service condition.");

  script_tag(name:"affected", value:"Windows 10 for 32-bit Systems

  Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4034668");
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
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.10240.0", test_version2:"11.0.10240.17532"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.10240.0 - 11.0.10240.17532\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
