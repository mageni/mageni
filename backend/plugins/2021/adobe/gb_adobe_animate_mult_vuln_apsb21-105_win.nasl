# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.818872");
  script_version("2021-12-03T04:02:27+0000");
  script_cve_id("CVE-2021-40733", "CVE-2021-42266", "CVE-2021-42267", "CVE-2021-42268",
                "CVE-2021-42269", "CVE-2021-42270", "CVE-2021-42271", "CVE-2021-42272",
                "CVE-2021-42524", "CVE-2021-42525");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-03 07:32:50 +0000 (Fri, 03 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-11-19 09:11:50 +0530 (Fri, 19 Nov 2021)");
  script_name("Adobe Animate Multiple Vulnerabilities (APSB21-105) - Windows");

  script_tag(name:"summary", value:"Adobe Animate is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - NULL Pointer Dereference error.

  - Use After Free error");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to
  execute arbitrary code and conduct privilege escalation on the affected
  system.");

  script_tag(name:"affected", value:"Adobe Animate 21.0.9 and earlier versions on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Animate 21.0.10 or 22.0 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/animate/apsb21-105.html");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"21.0.10"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"21.0.10 or 22.0", install_path:path);
  security_message(data: report);
  exit(0);
}
exit(99);
