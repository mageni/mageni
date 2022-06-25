###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-106.nasl 2015-10-14 10:03:00 +0530  Oct$
#
# Microsoft Internet Explorer Multiple Vulnerabilities (3096441)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805761");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2015-2482", "CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6046",
                "CVE-2015-6047", "CVE-2015-6048", "CVE-2015-6049", "CVE-2015-6050",
                "CVE-2015-6051", "CVE-2015-6052", "CVE-2015-6053", "CVE-2015-6055",
                "CVE-2015-6056", "CVE-2015-6059", "CVE-2015-6184");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2015-10-14 10:03:00 +0530 (Wed, 14 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (3096441)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-106.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple improper handling memory objects,

  - Improper permissions validation, allowing a script to be run with elevated
    privileges.

  - An error in 'CAttrArray' object implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to corrupt memory and potentially execute arbitrary code in the
  context of the current user.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version
  7.x/8.x/9.x/10.x/11.x");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3096441");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-106");

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
  Vulnerable_range = "7.0.6002.18000 - 7.0.6002.19487";
}
else if (dllVer =~ "^7\.0\.6002\.2"){
  Vulnerable_range = "7.0.6002.23000 - 7.0.6002.23797";
}
else if (dllVer =~ "^8\.0\.6001\.1"){
  Vulnerable_range = "8.0.6001.18000 - 8.0.6001.19689";
}
else if (dllVer =~ "^8\.0\.6001\.2"){
  Vulnerable_range = "8.0.6001.20000 - 8.0.6001.23749";
}
else if (dllVer =~ "^9\.0\.8112\.1"){
  Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16707";
}
else if (dllVer =~ "^9\.0\.8112\.2"){
  Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20822";
}
else if (dllVer =~ "^8\.0\.7601\.1"){
  Vulnerable_range = "8.0.7601.17000 - 8.0.7601.19002";
}
else if (dllVer =~ "^8\.0\.7601\.2"){
  Vulnerable_range = "8.0.7601.22000 - 8.0.7601.23205";
}
else if (dllVer =~ "^10\.0\.9200\.1"){
  Vulnerable_range = "10.0.9200.16000 - 10.0.9200.17518";
}
else if (dllVer =~ "^10\.0\.9200\.2"){
  Vulnerable_range = "10.0.9200.21000 - 10.0.9200.21635";
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19487")||
     version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23797")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19689")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23749")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16707")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20822")){
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.17000", test_version2:"8.0.7601.19002")||
     version_in_range(version:dllVer, test_version:"8.0.7601.22000", test_version2:"8.0.7601.23205")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16707")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20822")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17518")||
     version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21635"))
  {
       VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.18056")){
     Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18056";
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17518")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21635")){
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.9600.18052")){
   Vulnerable_range = "less than 11.0.9600.18052";
   VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"10.0.10240.16566"))
  {
    Vulnerable_range = "Less than 10.0.10240.16566";
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
