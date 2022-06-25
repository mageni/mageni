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

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815010");
  script_version("2019-05-22T13:05:41+0000");
  script_cve_id("CVE-2018-4461");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-22 13:05:41 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-27 17:59:12 +0530 (Wed, 27 Mar 2019)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Xcode Arbitrary Code Execution Vulnerability (HT209606)");

  script_tag(name:"summary", value:"This host is installed with Apple Xcode
  and is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a memory corruption issue
  related to improper input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary code with kernel privileges.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 10.2");

  script_tag(name:"solution", value:"Upgrade to Apple Xcode 10.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209606");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || version_is_less(version:osVer, test_version:"10.13.6")){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
  exit(0);
}

xcVer = infos['version'];
xcpath = infos['location'];

if(version_is_less(version:xcVer, test_version:"10.2"))
{
  report = report_fixed_ver(installed_version:xcVer, fixed_version:"10.2", install_path:xcpath);
  security_message(data:report);
  exit(0);
}
exit(0);
