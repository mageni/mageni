# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821329");
  script_version("2022-12-15T11:15:36+0000");
  script_cve_id("CVE-2022-44498", "CVE-2022-44499", "CVE-2022-44450", "CVE-2022-44502");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-15 11:15:36 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-15 11:54:53 +0530 (Thu, 15 Dec 2022)");
  script_name("Adobe Illustrator Multiple Vulnerabilities (APSB22-60) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Illustrator is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple Out-of-bounds Read error.

  - Improper Input Validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution and memory leak on the system.");

  script_tag(name:"affected", value:"Adobe Illustrator 26.5.1 and earlier,
  27.0 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Illustrator 26.5.2 or
  27.0.1 or later. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/illustrator/apsb22-60.html");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Illustrator/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version: "27.0")){
  fix = "27.0.1 or later";
}
else if(version_in_range(version:vers, test_version:"26.0", test_version2:"26.5.1")){
  fix = "26.5.2 or later";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
