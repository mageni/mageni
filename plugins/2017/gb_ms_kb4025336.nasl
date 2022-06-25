###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4025336)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811518");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8594", "CVE-2017-8602", "CVE-2017-0170", "CVE-2017-8463",
                "CVE-2017-8606", "CVE-2017-8607", "CVE-2017-8467", "CVE-2017-8486",
                "CVE-2017-8495", "CVE-2017-8608", "CVE-2017-8618", "CVE-2017-8556",
                "CVE-2017-8557", "CVE-2017-8561", "CVE-2017-8562", "CVE-2017-8563",
                "CVE-2017-8564", "CVE-2017-8565", "CVE-2017-8573", "CVE-2017-8577",
                "CVE-2017-8578", "CVE-2017-8580", "CVE-2017-8581", "CVE-2017-8582",
                "CVE-2017-8587", "CVE-2017-8588", "CVE-2017-8589", "CVE-2017-8590",
                "CVE-2017-8592");
  script_bugtraq_id(99397, 99396, 99412, 99394, 99414, 99416, 99390, 99419, 99399,
                    99398, 99439, 99410, 99431, 99402, 99401, 99400, 99389, 99409,
                    99408, 99429, 99428, 99421, 99423, 99425, 99424, 99427, 99426,
                    99413);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-07-12 10:05:45 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4025336)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4025336");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists,

  - When Microsoft Windows fails to properly handle objects in memory.

  - The way JavaScript engines render when handling objects in memory in
    Microsoft browsers.

  - Windows Explorer improperly handles executable files and shares during
    rename operations.

  - An affected Microsoft browser does not properly parse HTTP content.

  - Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - Microsoft Windows when Kerberos falls back to NT LAN Manager (NTLM)
    Authentication Protocol as the default authentication protocol.

  - Windows Kernel improperly handles objects in memory.

  - The Windows kernel fails to properly initialize a memory address,
    allowing an attacker to retrieve information that could lead to a Kernel
    Address Space Layout Randomization (KASLR) bypass.

  - PSObject wraps a CIM Instance.

  - Microsoft Graphics Component fails to properly handle objects in memory.

  - VBScript engine, when rendered in Internet Explorer, improperly handles
    objects in memory.

  - Microsoft Browsers improperly handle redirect requests.

  - Microsoft Windows when Kerberos fails to prevent tampering with the SNAME
    field during ticket exchange.

  - Internet Explorer improperly accesses objects in memory.

  - Windows System Information Console when it improperly parses
    XML input containing a reference to an external entity.

  - Windows Performance Monitor Console when it improperly parses XML
    input containing a reference to an external entity.

  - Microsoft WordPad parses specially crafted files.

  - Windows Search improperly handles objects in memory.

  - Windows Explorer attempts to open a non-existent file.

  - Windows improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to obtain information to further compromise the user's system,
  gain the same user rights as the current user, run arbitrary code in the
  context of another user, trick a user by redirecting the user
  to a specially crafted website, run processes in an elevated cretrieve the
  base address of the kernel driver from a compromised process, embed an
  ActiveX control marked 'safe for initialization' in an application or
  Microsoft Office document that hosts the Internet Explorer rendering engine,
  force the browser to send data that would otherwise be restricted to a
  destination web site of their choice, bypass Extended Protection for
  Authentication, read arbitrary files via an XML external entity (XXE)
  declaration and cause a denial of service.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025336");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.18737"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Win32k.sys",
                        file_version:fileVer, vulnerable_range:'Less than 6.3.9600.18737');
  security_message(data:report);
  exit(0);
}
exit(0);
