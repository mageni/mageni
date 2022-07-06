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
  script_oid("1.3.6.1.4.1.25623.1.0.148357");
  script_version("2022-07-05T03:13:38+0000");
  script_tag(name:"last_modification", value:"2022-07-05 03:13:38 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-05 02:03:24 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-32085", "CVE-2022-32087");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB Multiple DoS Vulnerabilities (MDEV-26407, MDEV-26437) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MariaDB is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-32085: Server crashes in Item_func_in::cleanup/Item::cleanup_processor (MDEV-26407,
  MDEV-24176)

  - CVE-2022-32087: Server crashes in Item_args::walk_args (MDEV-26437, MDEV-24176)");

  script_tag(name:"affected", value:"MariaDB version 10.8.x and prior.");

  script_tag(name:"solution", value:"Update to version 10.3.35, 10.4.25, 10.5.16, 10.6.8, 10.7.4,
  10.8.3 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-24176");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26407");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26437");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.3.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.35");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.4.0", test_version_up: "10.4.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.25");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.5.0", test_version_up: "10.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.6.0", test_version_up: "10.6.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.8");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.7.0", test_version_up: "10.7.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.7.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.8.0", test_version_up: "10.8.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
