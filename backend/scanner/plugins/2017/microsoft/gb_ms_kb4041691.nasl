###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4041691)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812026");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8717", "CVE-2017-11763", "CVE-2017-11765", "CVE-2017-11769",
                "CVE-2017-8718", "CVE-2017-8726", "CVE-2017-8727", "CVE-2017-11771",
                "CVE-2017-11772", "CVE-2017-11779", "CVE-2017-11780", "CVE-2017-11781",
                "CVE-2017-11782", "CVE-2017-11783", "CVE-2017-11785", "CVE-2017-11790",
                "CVE-2017-11793", "CVE-2017-11798", "CVE-2017-11799", "CVE-2017-11800",
                "CVE-2017-11802", "CVE-2017-11804", "CVE-2017-11808", "CVE-2017-11809",
                "CVE-2017-11810", "CVE-2017-11811", "CVE-2017-11812", "CVE-2017-11814",
                "CVE-2017-11815", "CVE-2017-11816", "CVE-2017-11817", "CVE-2017-11818",
                "CVE-2017-11822", "CVE-2017-11823", "CVE-2017-11824", "CVE-2017-11829",
                "CVE-2017-8689", "CVE-2017-8693", "CVE-2017-11762", "CVE-2017-8694",
                "CVE-2017-8715", "CVE-2017-13080");
  script_bugtraq_id(101108, 101100, 101163, 101161, 101109, 101111, 101112, 101162,
                    101084, 101142, 101114, 101116, 101166, 101110, 101140, 101143,
                    101144, 101149, 101077, 101141, 101125, 101126, 101127, 101130,
                    101131, 101135, 101137, 101081, 101138, 101139, 101093, 101136,
                    101094, 101095, 101101, 101122, 101102, 101099, 101213, 101128,
                    101096, 101274);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-10-11 10:50:05 +0530 (Wed, 11 Oct 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4041691)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4041691");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A spoofing vulnerability in the Windows implementation of wireless networking (KRACK)

  - An error when Windows improperly handles calls to Advanced Local Procedure
    Call (ALPC).

  - An error in the Microsoft Server Block Message (SMB) when an attacker sends
    specially crafted requests to the server.

  - An error in the Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space Layout Randomization
    (ASLR) bypass.

  - An error in certain Trusted Platform Module (TPM) chipsets.

  - An error when Internet Explorer improperly accesses objects in memory.

  - An error in the way that certain Windows components handle the loading of
    DLL files.

  - An error when the Windows kernel improperly handles objects in memory.

  - An error when the Windows font library improperly handles specially crafted
    embedded fonts.

  - An error when the Microsoft Windows Graphics Component improperly handles
    objects in memory.

  - An error when the Windows kernel-mode driver fails to properly handle objects
    in memory.

  - An error in the way the scripting engine handle objects in memory in Microsoft
    browsers.

  - An error in the way that the scripting engine handles objects in memory in
    Microsoft Edge.

  - An error in Device Guard that could allow an attacker to inject malicious code
    into a Windows PowerShell session.

  - An error in the Microsoft JET Database Engine that could allow remote code
    execution on an affected system.

  - An error when Internet Explorer improperly handles objects in memory.

  - An error when the Windows Graphics Component improperly handles objects in memory.

  - An error in the way that the scripting engine handles objects in memory in
    Internet Explorer.

  - An error when the Windows Update Delivery Optimization does not properly enforce
    file share permissions.

  - An error in Windows Domain Name System (DNS) DNSAPI.

  - An error in the default Windows SMB Server configuration which allows anonymous
    users to remotely access certain named pipes that are also configured to allow
    anonymous access to users who are logged on locally.

  - An error when Windows Search improperly handles objects in memory.

  - An error in Microsoft Windows storage when it fails to validate an integrity-level
    check.

  - An error in the way affected Microsoft scripting engines render when handling
    objects in memory in Microsoft Edge.

  - when Internet Explorer improperly accesses objects in memory via the Microsoft
    Windows Text Services Framework.

  - An error when the Windows kernel improperly initializes objects in memory.

  - An error in the way that the Windows Graphics Device Interface (GDI) handles
    objects in memory, allowing an attacker to retrieve information from a targeted
    system.

  - An error in the way that the Windows SMB Server handles certain requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the security context of the local system, conduct NTLM
  dictionary attacks, cause the affected system to crash, take complete control
  of an affected system, obtain sensitive information to further compromise the
  user's system, inject code into a trusted PowerShell process, run processes
  in an elevated context, inject code code in kernel mode and gain elevated
  privileges.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2016

  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4041691");
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

if(hotfix_check_sp(win2016:1, win10:1, win10x64:1) <= 0){
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

if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.1769"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.14393.0 - 11.0.14393.1769\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
