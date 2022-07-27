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
  script_oid("1.3.6.1.4.1.25623.1.0.147568");
  script_version("2022-02-02T05:33:50+0000");
  script_tag(name:"last_modification", value:"2022-02-02 11:01:49 +0000 (Wed, 02 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-02 04:52:18 +0000 (Wed, 02 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2021-46662");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB DoS Vulnerability (MDEV-25637, MDEV-22464) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MariaDB allows a set_var.cc application crash via certain uses
  of an UPDATE statement in conjunction with a nested subquery.");

  script_tag(name:"affected", value:"MariaDB version 10.3.x through 10.6.x.");

  script_tag(name:"solution", value:"Update to version 10.3.32, 10.4.22, 10.5.13, 10.6.5 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-25637");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-22464");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "10.3.0", test_version2: "10.3.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.32");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.4.0", test_version2: "10.4.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.22");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.13");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.6.0", test_version2: "10.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
