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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:premiere_rush";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819909");
  script_version("2022-01-06T05:11:00+0000");
  script_cve_id("CVE-2021-40783", "CVE-2021-40784", "CVE-2021-43021", "CVE-2021-43022",
                "CVE-2021-43023", "CVE-2021-43024", "CVE-2021-43025", "CVE-2021-43026",
                "CVE-2021-43028", "CVE-2021-43029", "CVE-2021-43030", "CVE-2021-43746",
                "CVE-2021-43747", "CVE-2021-43748", "CVE-2021-43749", "CVE-2021-43750");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-01-06 10:37:42 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-03 08:25:27 +0530 (Mon, 03 Jan 2022)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Premiere Rush Multiple Vulnerabilities (APSB21-101) - Windows");

  script_tag(name:"summary", value:"Adobe Premiere Rush is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Access of Memory Location After End of Buffer.

  - Access of Uninitialized Pointer.

  - Improper Input Validation.

  - Multiple NULL Pointer Dereference errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, escalate privileges or cause denial of service on
  the affected system.");

  script_tag(name:"affected", value:"Adobe Premiere Rush versions 1.5.16 and prior.");

  script_tag(name:"solution", value:"Update Adobe Premiere Rush to version 2.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/premiere_rush/apsb21-101.html");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_premiere_rush_detect_win.nasl");
  script_mandatory_keys("adobe/premiererush/win/detected");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:'2.0', install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
