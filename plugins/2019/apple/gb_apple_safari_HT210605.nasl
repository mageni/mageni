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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815476");
  script_version("2019-10-01T10:38:58+0000");
  script_cve_id("CVE-2019-8654", "CVE-2019-8725");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-01 10:38:58 +0000 (Tue, 01 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-09-27 18:07:39 +0530 (Fri, 27 Sep 2019)");
  script_name("Apple Safari Security Updates (HT210605)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An inconsistent user interface issue related to improper state management.

  - An improper handling of service worker lifetime.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  conduct spoofing attack and leak private browsing history.");

  script_tag(name:"affected", value:"Apple Safari versions before 13.0.1
  on macOS 10.14.x and macOS 10.13.x");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 13.0.1 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-in/HT210605");
  script_xref(name:"URL", value:"https://support.apple.com/downloads/safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version", "ssh/login/osx_name");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

osName = get_kb_item("ssh/login/osx_name");
osVer = get_kb_item("ssh/login/osx_version");
if((!osName && "Mac OS X" >!< osName) || !osVer){
  exit (0);
}

if(version_in_range(version:osVer, test_version:"10.14", test_version2:"10.14.5"))
{
  fix = "Upgrade Apple Mac OS X to version 10.14.6 and Update Apple Safari to version 13.0.1";
  installedVer = "Apple Mac OS X " + osVer ;
}
else if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5"))
{
  fix = "Upgrade Apple Mac OS X to version 10.13.6 and Update Apple Safari to version 13.0.1";
  installedVer = "Apple Mac OS X " + osVer ;
}

else if(osVer == "10.13.6" || osVer == "10.14.6")
{
  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
  safVer = infos['version'];
  path = infos['location'];

  if(version_is_less(version:safVer, test_version:"13.0.1"))
  {
    fix = "13.0.1";
    installedVer = "Apple Safari " + safVer ;
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:installedVer, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
