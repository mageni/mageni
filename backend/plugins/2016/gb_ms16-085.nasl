###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Edge Multiple Vulnerabilities (3169999)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807346");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2016-3244", "CVE-2016-3246", "CVE-2016-3248", "CVE-2016-3259",
                "CVE-2016-3260", "CVE-2016-3264", "CVE-2016-3265", "CVE-2016-3269",
                "CVE-2016-3271", "CVE-2016-3273", "CVE-2016-3274", "CVE-2016-3276",
                "CVE-2016-3277");
  script_bugtraq_id(91599, 91602, 91578, 91581, 91580, 91598, 91573, 91595, 91586,
                    91576, 91591, 91593, 91596);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-07-13 08:14:54 +0530 (Wed, 13 Jul 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Multiple Vulnerabilities (3169999)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-085.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A security feature bypass exists when Microsoft Edge does not properly
    implement Address Space Layout Randomization (ASLR).

  - Multiple remote code execution vulnerabilities exist when Microsoft Edge
    improperly accesses objects in memory.

  - Multiple remote code execution vulnerabilities exist in the way that the
    Chakra JavaScript engine renders when handling objects in memory

  - A spoofing vulnerability exists when a Microsoft browser does not properly
    parse HTTP content.

  - A spoofing vulnerability exists when the Microsoft Browser in reader mode
    does not properly parse HTML content.

  - An information disclosure vulnerability exists when the Microsoft Browser
    improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to trick a user into loading a page containing malicious content,
  to trick the user into opening the .pdf file and read information in the context
  of the current user and to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3163912");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3172985");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-085");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Edge/Installed");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgedllVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgedllVer){
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:edgedllVer, test_version:"11.0.10240.17024"))
  {
    Vulnerable_range = "Less than 11.0.10240.17024";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgedllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.493"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.493";
    VULN = TRUE ;
  }
}


if(VULN)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgedllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
