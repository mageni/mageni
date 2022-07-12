# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:dreamweaver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815250");
  script_version("2019-07-12T06:29:03+0000");
  script_cve_id("CVE-2019-7956");
  script_bugtraq_id(109088);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-12 06:29:03 +0000 (Fri, 12 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-11 11:53:01 +0530 (Thu, 11 Jul 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Dreamweaver Privilege Escalation Vulnerability(APSB19-40)-Windows");

  script_tag(name:"summary", value:"The host is installed with Adobe Dreamweaver
  and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insecure library loading
  or dll hijacking vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to
  gain elevated privileges on the affected system.");

  script_tag(name:"affected", value:"Adobe Dreamweaver before version 18.0.0.10136,
  19.x before version 19.0.0.18193 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Dreamweaver 2018/2019 Release or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/download-install/kb/creative-cloud-apps-download.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb19-40.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_dreamweaver_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Adobe/Dreamweaver/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("smb_nt.inc");
include("secpod_reg.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

AppVer = fetch_file_version(sysPath:path, file_name:"Dreamweaver.exe");
if(!AppVer){
  AppVer = fetch_file_version(sysPath:path, file_name:"Adobe Dreamweaver CC 2018\Dreamweaver.exe");
}
if(!AppVer) exit(0);

#Adobe Dreamweaver CC 2019 Release == 19.0.0.11193
if(AppVer =~ "^19" && version_is_less(version:AppVer, test_version:"19.0.0.11193"))
{
  report =  report_fixed_ver(installed_version:AppVer, fixed_version:"2019 Release", install_path:path);
  security_message(data:report);
  exit(0);
}

#Adobe Dreamweaver CC 2018 Release == 18.0.0.10136
else if(version_is_less(version:AppVer, test_version:"18.0.0.10136"))
{
  report =  report_fixed_ver(installed_version:AppVer, fixed_version:"2018 Release", install_path:path + "\Adobe Dreamweaver CC 2018");
  security_message(data:report);
  exit(0);
}
exit(99);
