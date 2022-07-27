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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145119");
  script_version("2021-01-12T08:45:58+0000");
  script_tag(name:"last_modification", value:"2021-01-12 11:05:42 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-12 08:39:57 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-28912");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB Named Pipe Permission Vulnerability (MDEV-24040) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to a named pipe permission vulnerability.");

  script_tag(name:"insight", value:"With MariaDB running on Windows, when local clients connect to the server
  over named pipes, it's possible for an unprivileged user with an ability to run code on the server machine
  to intercept the named pipe connection and act as a man-in-the-middle, gaining access to all the data passed
  between the client and the server, and getting the ability to run SQL commands on behalf of the connected
  user. This occurs because of an incorrect security descriptor.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MariaDB versions 10.1, 10.2, 10.3, 10.4 and 10.5.");

  script_tag(name:"solution", value:"Update to version 10.1.48, 10.2.35, 10.3.26, 10.4.16, 10.5.7 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-24040");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "10.1.0", test_version2: "10.1.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.48");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.2.0", test_version2: "10.2.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.35");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.3.0", test_version2: "10.3.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.26");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.4.0", test_version2: "10.4.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
