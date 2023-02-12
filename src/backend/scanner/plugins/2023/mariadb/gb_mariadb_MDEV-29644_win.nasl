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

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149186");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-23 06:45:09 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-47015");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB DoS Vulnerability (MDEV-29644) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible for function spider_db_mbase::print_warnings to
  dereference a null pointer.");

  script_tag(name:"affected", value:"MariaDB version 10.3.x through 10.11.x.");

  script_tag(name:"solution", value:"Update to version 10.3.37, 10.4.27, 10.5.18, 10.6.11, 10.7.7,
  10.8.6, 10.9.4, 10.10.2, 10.11.1 or later.");

  script_xref(name:"URL", value:"https://github.com/MariaDB/server/commit/be0a46b3d52b58956fd0d47d040b9f4514406954");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-29644");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "10.3.0", test_version_up: "10.3.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.37");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.4.0", test_version_up: "10.4.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.27");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.5.0", test_version_up: "10.5.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.18");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.6.0", test_version_up: "10.6.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.7.0", test_version_up: "10.7.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.7.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.8.0", test_version_up: "10.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.9.0", test_version_up: "10.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.9.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.10.0", test_version_up: "10.10.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.10.2");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.11.0", test_version_up: "10.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.11.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
