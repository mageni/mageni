###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Vulnerabilities (KB4021558)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810943");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2017-8517", "CVE-2017-8519", "CVE-2017-8522", "CVE-2017-8524",
                "CVE-2017-8529", "CVE-2017-8547", "CVE-2016-3326");
  script_bugtraq_id(98895, 98899, 98926, 98930, 98953, 98932, 92287);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2017-06-14 12:38:50 +0530 (Wed, 14 Jun 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (KB4021558)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security updates KB4021558.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple errors in the way JavaScript scripting engines handle objects in
  memory in Microsoft browsers.

  - Multiple errors when microsoft scripting engines do not properly handle
  objects in memory.

  - Multiple errors when Microsoft browsers improperly handle objects in memory.

  - An error when Internet Explorer improperly accesses objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain information to further compromise the users system, execute
  arbitrary code in the context of the current user and detect specific files
  on the user's computer.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x,
  10.x and 11.x");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4021558");
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

if(hotfix_check_sp(win2008:3, win2008x64:3, win7:2, win7x64:2, win2008r2:2,
                   win2012:1,  win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^(9|1[01])\."){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
sllVer = fetch_file_version(sysPath:iePath, file_name:"Sqmapi.dll");

if(!iedllVer && !sllVer){
  exit(0);
}

##Server 2008
if(hotfix_check_sp(win2008:3, win2008x64:3) > 0 && iedllVer)
{
  if(version_in_range(version:iedllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16905"))
  {
    Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16905";
    VULN = TRUE ;
  }
  else if(version_in_range(version:iedllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.21016"))
  {
    Vulnerable_range = "9.0.8112.20000 - 9.0.8112.21016";
    VULN = TRUE ;
  }
}

# Win 2012
else if(hotfix_check_sp(win2012:1) > 0 && sllVer)
{
  if(version_is_less(version:sllVer, test_version:"6.2.9200.16384"))
  {
    report = 'File checked:     ' + iePath + "\Sqmapi.dll" + '\n' +
             'File version:     ' + sllVer  + '\n' +
             'Vulnerable range: Less than 6.2.9200.16384\n' ;
    security_message(data:report);
    exit(0);
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win7:2, win7x64:2, win2008r2:2) > 0 && iedllVer)
{
  if(version_in_range(version:iedllVer, test_version:"11.0", test_version2:"11.0.9600.18697"))
  {
     Vulnerable_range = "11.0 - 11.0.9600.18697";
     VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + iePath + "\Mshtml.dll" + '\n' +
           'File version:     ' + iedllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
