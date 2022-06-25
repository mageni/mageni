###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Vulnerabilities (KB4036586)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811760");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2017-8529", "CVE-2017-8733", "CVE-2017-8736", "CVE-2017-8741",
                "CVE-2017-8747", "CVE-2017-8748", "CVE-2017-8749", "CVE-2017-8750");
  script_bugtraq_id(100737, 98953, 100764, 100743, 100766, 100770, 100771, 100765);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 16:28:36 +0530 (Wed, 13 Sep 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (KB4036586)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security updates KB4036586.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Microsoft scripting engines do not properly handle objects in memory.

  - Internet Explorer improperly handles specific HTML content.

  - An error in Microsoft browsers due to improper parent domain verification
  in certain functionality.

  - An error in the way that Microsoft browser JavaScript engines render content
  when handling objects in memory.

  - Internet Explorer improperly accesses objects in memory.

  - An error in the way that Microsoft browser JavaScript engines render content
  when handling objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user, gain access to
  potentially sensitive information, spoof content or serve as a pivot and detect
  specific files on the user's computer.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x,
  10.x and 11.x");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4036586");

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
if(!iedllVer){
  exit(0);
}

##Server 2008
if(hotfix_check_sp(win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"9.0.8112.21046"))
  {
    Vulnerable_range = "Less than 9.0.8112.21046";
    VULN = TRUE ;
  }
}

# Win 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"10.0.9200.22248"))
  {
    Vulnerable_range = "Less than 10.0.9200.22248";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"11.0.9600.18792"))
  {
     Vulnerable_range = "Less than 11.0.9600.18792";
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
exit(0);
