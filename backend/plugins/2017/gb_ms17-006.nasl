###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Vulnerabilities (4013073)
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

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810625");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0008", "CVE-2017-0009", "CVE-2017-0012", "CVE-2017-0018",
                "CVE-2017-0033", "CVE-2017-0037", "CVE-2017-0040", "CVE-2017-0049",
                "CVE-2017-0059", "CVE-2017-0130", "CVE-2017-0149", "CVE-2017-0154");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-15 12:07:36 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (4013073)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS17-006.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple errors in the components handling objects in memory.

  - Microsoft browsers improperly access objects in memory.

  - An error in Microsoft browser which does not properly parse HTTP responses.

  - Multiple errors in JScript and VBScript engines rendering when handling
    objects in memory.

  - An error in Internet Explorer which does not properly enforce cross-domain
    policies.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges, gain access to potentially sensitive
  information, execute arbitrary code in the context of the current user and
  conduct spoofing attacks.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version
  9.x/10.x/11.x");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4013073");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-006");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3, win2012:1,
                   win7:2, win7x64:2, win2008r2:2, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"mshtml.dll");
oleVer = fetch_file_version(sysPath:iePath, file_name:"inetcomm.dll");
edgeVer = fetch_file_version(sysPath:iePath, file_name:"edgehtml.dll");
if(!iedllVer && !oleVer && !edgeVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3, winVistax64:3, win2008x64:3) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16870") && iedllVer)
  {
    Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16870";
    VULN = TRUE ;
  }
  else if(version_in_range(version:iedllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20984") && iedllVer)
  {
    Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20984";
    VULN = TRUE ;
  }

  else if(version_is_less(version:oleVer, test_version:"6.0.6002.19728") && oleVer)
  {
    Vulnerable_range = "Less than 6.0.6002.19728";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:oleVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24051") && oleVer)
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24051";
    VULN1 = TRUE ;
  }
}

## Win 2012
else if(hotfix_check_sp(win2012:1) > 0 && iedllVer)
{
  if(version_is_less(version:iedllVer, test_version:"10.0.9200.22104"))
  {
    Vulnerable_range = "Less than 10.0.9200.22104";
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1) > 0 && iedllVer)
{
  if(version_is_less(version:iedllVer, test_version:"11.0.9600.18618"))
  {
    Vulnerable_range = "Less than 11.0.9600.18618";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0 && edgeVer)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17319"))
  {
    Vulnerable_range = "Less than 11.0.10240.17319";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.838"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.839";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.952"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.952";
    VULN2 = TRUE ;
  }
}


if(VULN)
{
  report = 'File checked:     ' + iePath + "\mshtml.dll" + '\n' +
           'File version:     ' + iedllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN1)
{
  report = 'File checked:     ' + iePath + "\inetcomm.dll" + '\n' +
           'File version:     ' + oleVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN2)
{
  report = 'File checked:     ' + iePath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
