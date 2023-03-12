# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.826923");
  script_version("2023-02-21T10:09:30+0000");
  script_cve_id("CVE-2023-22236", "CVE-2023-22243", "CVE-2023-22246");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-02-21 10:09:30 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-16 12:12:21 +0530 (Thu, 16 Feb 2023)");
  script_name("Adobe Animate Code Execution Vulnerabilities (APSB23-15) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe Animate February 2023 update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due,

  - An use after free error.

  - A stack-based buffer overflow error.

  - A heap-based buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Adobe Animate 2022 versions prior to 22.0.9 and
  2023 versions prior to 23.0.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Animate 2022 to 22.0.9 or
  later, 2023 to 23.0.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/animate/apsb23-15.html");
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
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

if(version_is_equal(version:vers, test_version:"23.0.0") ||
   version_in_range(version:vers, test_version:"22.0", test_version2:"22.0.8"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"22.0.9 or 23.0.1 or later", install_path:path);
  security_message(data: report);
  exit(0);
}
exit(99);
