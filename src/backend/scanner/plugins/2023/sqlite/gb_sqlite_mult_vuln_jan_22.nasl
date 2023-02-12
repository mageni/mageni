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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126291");
  script_version("2023-01-12T10:12:15+0000");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-10 10:28:38 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-35525", "CVE-2020-35527");

  script_name("SQLite < 3.32.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-35525: A potential null pointer derreference was found in the `INTERSEC` query
  processing.

  - CVE-2020-35527: There is an out of bounds access problem through `ALTER TABLE` for views that
  have a nested `FROM` clause.");

  script_tag(name:"affected", value:"SQLite prior to version 3.32.0.");

  script_tag(name:"solution", value:"Update to version 3.32.0 or later");

  script_xref(name:"URL", value:"https://www.sqlite.org/src/info/a67cf5b7d37d5b14");
  script_xref(name:"URL", value:"https://www.sqlite.org/src/info/c431b3fd8fd0f6a6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.32.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.32.0", install_path: location);
  security_message(data: report, port: 0);
  exit(0);
}

exit( 99 );
