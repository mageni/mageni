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

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148641");
  script_version("2022-08-29T04:01:26+0000");
  script_tag(name:"last_modification", value:"2022-08-29 04:01:26 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-29 03:48:34 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2022-38791");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB DoS Vulnerability (MDEV-28719) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MariaDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"compress_write in extra/mariabackup/ds_compress.cc does not
  release data_mutex upon a stream write failure, which allows local users to trigger a deadlock.");

  script_tag(name:"affected", value:"MariaDB version 10.3.x through 10.9.x.");

  script_tag(name:"solution", value:"Update to version 10.3.36, 10.4.26, 10.5.17, 10.6.9, 10.7.5,
  10.8.4, 10.9.2 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28719");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "10.3.0", test_version_up: "10.3.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.36");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.4.0", test_version_up: "10.4.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.26");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.5.0", test_version_up: "10.5.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.17");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.6.0", test_version_up: "10.6.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.7.0", test_version_up: "10.7.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.7.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.8.0", test_version_up: "10.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.9.0", test_version_up: "10.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.9.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
