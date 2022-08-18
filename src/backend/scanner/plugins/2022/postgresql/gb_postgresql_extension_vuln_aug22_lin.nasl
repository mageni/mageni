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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148596");
  script_version("2022-08-16T10:20:04+0000");
  script_tag(name:"last_modification", value:"2022-08-16 10:20:04 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-16 02:18:07 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-2625");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 10.x < 10.22, 11.x < 11.17, 12.x < 12.12, 13.x < 13.8, 14.x < 14.5 Extension Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to a vulnerability where extension scripts
  replace objects not belonging to the extension.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Some extensions use CREATE OR REPLACE or CREATE IF NOT EXISTS
  commands. Some don't adhere to the documented rule to target only objects known to be extension
  members already. An attack requires permission to create non-temporary objects in at least one
  schema, ability to lure or wait for an administrator to create or update an affected extension in
  that schema, and ability to lure or wait for a victim to use the object targeted in CREATE OR
  REPLACE or CREATE IF NOT EXISTS.");

  script_tag(name:"impact", value:"Given all three prerequisites, the attacker can run arbitrary
  code as the victim role, which may be a superuser. Known-affected extensions include both
  PostgreSQL-bundled and non-bundled extensions. PostgreSQL is blocking this attack in the core
  server, so there's no need to modify individual extensions.");

  script_tag(name:"affected", value:"PostgreSQL version 10.x, 11.x, 12.x, 13.x and 14.x.");

  script_tag(name:"solution", value:"Update to version 10.22, 11.17, 12.12, 13.8, 14.5 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2022-2625/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-145-138-1212-1117-1022-and-15-beta-3-released-2496/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "10.0", test_version_up: "10.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0", test_version_up: "11.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "12.0", test_version_up: "12.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "13.0", test_version_up: "13.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
