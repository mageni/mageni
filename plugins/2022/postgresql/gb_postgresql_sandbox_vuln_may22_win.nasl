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
  script_oid("1.3.6.1.4.1.25623.1.0.148121");
  script_version("2022-05-16T12:26:34+0000");
  script_tag(name:"last_modification", value:"2022-05-16 12:26:34 +0000 (Mon, 16 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-16 04:50:30 +0000 (Mon, 16 May 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2022-1552");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 10.x < 10.21, 11.x < 11.16, 12.x < 12.11, 13.x < 13.7, 14.x < 14.3 Privilege Escalation Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Autovacuum, REINDEX, CREATE INDEX, REFRESH MATERIALIZED VIEW,
  CLUSTER, and pg_amcheck made incomplete efforts to operate safely when a privileged user is
  maintaining another user's objects. Those commands activated relevant protections too late or not
  at all.");

  script_tag(name:"impact", value:"An attacker having permission to create non-temp objects in at
  least one schema could execute arbitrary SQL functions under a superuser identity.");

  script_tag(name:"affected", value:"PostgreSQL version 10.x, 11.x, 12.x, 13.x and 14.x.");

  script_tag(name:"solution", value:"Update to version 10.21, 11.16, 12.11, 13.7, 14.3 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-143-137-1211-1116-and-1021-released-2449/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2022-1552/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "10.0", test_version_up: "10.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0", test_version_up: "11.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "12.0", test_version_up: "12.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "13.0", test_version_up: "13.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
