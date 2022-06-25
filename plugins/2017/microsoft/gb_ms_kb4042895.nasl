###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4042895)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811921");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-11762", "CVE-2017-8694", "CVE-2017-8715", "CVE-2017-8717",
                "CVE-2017-11763", "CVE-2017-11765", "CVE-2017-11769", "CVE-2017-8718",
                "CVE-2017-8726", "CVE-2017-8727", "CVE-2017-11771", "CVE-2017-11772",
                "CVE-2017-11779", "CVE-2017-11780", "CVE-2017-11781", "CVE-2017-11783",
                "CVE-2017-11784", "CVE-2017-11785", "CVE-2017-11790", "CVE-2017-11793",
                "CVE-2017-11798", "CVE-2017-11799", "CVE-2017-11800", "CVE-2017-11802",
                "CVE-2017-11804", "CVE-2017-11808", "CVE-2017-11809", "CVE-2017-11810",
                "CVE-2017-11811", "CVE-2017-11816", "CVE-2017-11817", "CVE-2017-11818",
                "CVE-2017-11822", "CVE-2017-11823", "CVE-2017-11824", "CVE-2017-8689",
                "CVE-2017-8693", "CVE-2017-11814", "CVE-2017-11815", "CVE-2017-13080");
  script_bugtraq_id(101108, 101100, 101163, 101161, 101109, 101111, 101112, 101162,
                    101084, 101142, 101114, 101116, 101166, 101110, 101140, 101144,
                    101147, 101149, 101077, 101141, 101125, 101126, 101127, 101130,
                    101131, 101135, 101137, 101081, 101138, 101094, 101095, 101101,
                    101122, 101102, 101099, 101128, 101096, 101093, 101136, 101274);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-10-11 08:47:24 +0530 (Wed, 11 Oct 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4042895)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4042895");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A spoofing vulnerability in the Windows implementation of wireless networking (KRACK)

  - The Universal CRT _splitpath was not handling multi byte strings correctly,
    which caused apps to fail when accessing multi byte filenames.

  - The Universal CRT caused the linker (link.exe) to stop working for large
    projects.

  - The MSMQ performance counter (MSMQ Queue) may not populate queue instances
    when the server hosts a clustered MSMQ role.

  - The Lock Workstation policy for smart cards where, in some cases, the system
    doesn't lock when you remove the smart card.

  - Issue with form submissions in Internet Explorer.

  - Issue with URL encoding in Internet Explorer.

  - Issue that prevents an element from receiving focus in Internet Explorer.

  - Issue with the docking and undocking of Internet Explorer windows.

  - Issue with the rendering of a graphics element in Internet Explorer.

  - Issue caused by a pop-up window in Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the security context of the local system, take complete
  control of an affected system, bypass certain security restrictions, gain access
  to potentially sensitive information, conduct a denial-of-service condition and
  gain privileged access.");

  script_tag(name:"affected", value:"Windows 10 for 32-bit Systems

  Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4042895");
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

if(version_in_range(version:edgeVer, test_version:"11.0.10240.0", test_version2:"11.0.10240.17642"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.10240.0 - 11.0.10240.17642\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
