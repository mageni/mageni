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

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126102");
  script_version("2022-08-05T12:42:56+0000");
  script_tag(name:"last_modification", value:"2022-08-05 12:42:56 +0000 (Fri, 05 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-05 12:28:38 +0000 (Fri, 05 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-35737");

  script_name("SQLite 1.0.12 < 3.39.2 Improper Input Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to an improper input validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SQLite sometimes allows an array-bounds overflow if billions of
  bytes are used in a string argument to a C API.");

  script_tag(name:"affected", value:"SQLite versions starting from 1.0.12 and before 3.39.2.");

  script_tag(name:"solution", value:"Update to version 3.39.2 or later.");

  script_xref(name:"URL", value:"https://www.sqlite.org/cves.html");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/720344");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (! infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.12", test_version_up: "3.39.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.39.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
