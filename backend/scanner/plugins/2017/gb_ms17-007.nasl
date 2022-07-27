###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Edge Multiple Vulnerabilities (4013071)
#
# Authors:
# Kashinath <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810808");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0009", "CVE-2017-0010", "CVE-2017-0011", "CVE-2017-0012",
                "CVE-2017-0015", "CVE-2017-0017", "CVE-2017-0023", "CVE-2017-0032",
                "CVE-2017-0033", "CVE-2017-0034", "CVE-2017-0035", "CVE-2017-0037",
                "CVE-2017-0065", "CVE-2017-0066", "CVE-2017-0067", "CVE-2017-0068",
                "CVE-2017-0069", "CVE-2017-0070", "CVE-2017-0071", "CVE-2017-0094",
                "CVE-2017-0131", "CVE-2017-0132", "CVE-2017-0133", "CVE-2017-0134",
                "CVE-2017-0135", "CVE-2017-0136", "CVE-2017-0137", "CVE-2017-0138",
                "CVE-2017-0140", "CVE-2017-0141", "CVE-2017-0150", "CVE-2017-0151");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-15 08:29:28 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Multiple Vulnerabilities (4013071)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS17-007.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - The way affected Microsoft scripting engines render when handling objects in
    memory in Microsoft browsers.

  - Microsoft browser does not properly parse HTTP responses.

  - Microsoft Edge improperly accesses objects in memory.

  - Microsoft Windows PDF Library improperly handles objects in memory.

  - Microsoft Edge fails to correctly apply Same Origin Policy for HTML elements
    present in other browser windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user, gain access to
  potentially sensitive information, conduct spoofing attacks and bypass same
  origin policy.");

  script_tag(name:"affected", value:"Microsoft Windows 10 x32/x64

  Microsoft Windows Server 2016 x64

  Microsoft Windows 10 Version 1511 x32/x64

  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/4013429");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/4013198");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/4012606");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS17-007");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Edge/Installed");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-007");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17319"))
  {
    Vulnerable_range = "Less than 11.0.10240.17319";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.838"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.838";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.952"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.952";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
             'File version:     ' + edgeVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

exit(0);
