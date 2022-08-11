###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Vulnerabilities (3116180)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806646");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2015-6083", "CVE-2015-6134", "CVE-2015-6135", "CVE-2015-6136",
                "CVE-2015-6138", "CVE-2015-6139", "CVE-2015-6140", "CVE-2015-6141",
                "CVE-2015-6142", "CVE-2015-6143", "CVE-2015-6144", "CVE-2015-6145",
                "CVE-2015-6146", "CVE-2015-6147", "CVE-2015-6148", "CVE-2015-6149",
                "CVE-2015-6150", "CVE-2015-6151", "CVE-2015-6152", "CVE-2015-6153",
                "CVE-2015-6154", "CVE-2015-6155", "CVE-2015-6156", "CVE-2015-6157",
                "CVE-2015-6158", "CVE-2015-6159", "CVE-2015-6160", "CVE-2015-6161",
                "CVE-2015-6162", "CVE-2015-6164");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2015-12-09 11:34:00 +0530 (Wed, 09 Dec 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (3116180)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-124.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple errors caused by improperly accessing objects in memory.

  - Multiple XSS filter bypass errors.

  - An error in VBScript which improperly discloses the contents of its memory.

  - An error in the way that the VBScript engine renders when handling objects
  in memory in Internet Explorer.

  - An error when Internet Explorer does not properly enforce content types.

  - An error when Internet Explorer improperly discloses the contents of its
  memory.

  - An error when Internet Explorer fails to use the Address Space Layout
  Randomization (ASLR) security feature.

  - An error when Internet Explorer does not properly enforce cross-domain
  policies.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, gain access to sensitive information,
  elevate privileges, bypass certain security restrictions and execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version
  7.x/8.x/9.x/10.x/11.x");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3116180");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3104002");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-124");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1,  win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^([7-9|1[01])\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

if(dllVer =~ "^7\.0\.6002\.1"){
  Vulnerable_range = "7.0.6002.18000 - 7.0.6002.19536";
}
else if (dllVer =~ "^7\.0\.6002\.2"){
  Vulnerable_range = "7.0.6002.23000 - 7.0.6002.23846";
}
else if (dllVer =~ "^8\.0\.6001\.1"){
  Vulnerable_range = "8.0.6001.18000 - 8.0.6001.19704";
}
else if (dllVer =~ "^8\.0\.6001\.2"){
  Vulnerable_range = "8.0.6001.20000 - 8.0.6001.23764";
}

else if (dllVer =~ "^9\.0\.8112\.1"){
  Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16722";
}
else if (dllVer =~ "^9\.0\.8112\.2"){
  Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20837";
}
else if (dllVer =~ "^8\.0\.7601\.1"){
  Vulnerable_range = "8.0.7601.17000 - 8.0.7601.19057";
}
else if (dllVer =~ "^8\.0\.7601\.2"){
  Vulnerable_range = "8.0.7601.22000 - 8.0.7601.23261";
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19536")||
     version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23846")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19704")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23764")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16722")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20837")){
    VULN = TRUE ;
  }
}



else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.17000", test_version2:"8.0.7601.19057")||
     version_in_range(version:dllVer, test_version:"8.0.7601.22000", test_version2:"8.0.7601.23261")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16722")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20837")){
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17565"))
  {
    Vulnerable_range = "10.0.9200.16000 - 10.0.9200.17565";
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21683"))
  {
    Vulnerable_range = "10.0.9200.21000 - 10.0.9200.21683";
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.18124"))
  {
     Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18124";
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17567"))
  {
    Vulnerable_range = "10.0.9200.16000 - 10.0.9200.17567";
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21683"))
  {
    Vulnerable_range = "10.0.9200.20000 - 10.0.9200.21672";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.9600.18125"))
  {
    Vulnerable_range = "Less than 11.0.9600.18125";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.10240.16603"))
  {
    Vulnerable_range = "Less than 11.0.10240.16603";
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.19"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.19";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Mshtml.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
