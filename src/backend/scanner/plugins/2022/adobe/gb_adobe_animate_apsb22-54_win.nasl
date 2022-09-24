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

CPE = "cpe:/a:adobe:animate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826521");
  script_version("2022-09-19T10:11:35+0000");
  script_cve_id("CVE-2022-38411", "CVE-2022-38412");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-15 15:33:39 +0530 (Thu, 15 Sep 2022)");
  script_name("Adobe Animate Code Execution Vulnerabilities (APSB22-54) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe September update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due,

  - An out-of-bounds read error.

  - A heap-based buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Adobe Animate versions prior to 21.0.12 and
  22.x prior to 22.0.8 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Animate 21.0.12 or 22.0.8
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/animate/apsb22-54.html");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_animate_detect_win.nasl");
  script_mandatory_keys("Adobe/Animate/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"21.0.12") ||
   version_in_range(version:vers, test_version:"22.0", test_version2:"22.0.7"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"21.0.12 or 22.0.8 or later", install_path:path);
  security_message(data: report);
  exit(0);
}
exit(99);
