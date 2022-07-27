# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142405");
  script_version("2019-05-13T13:15:15+0000");
  script_tag(name:"last_modification", value:"2019-05-13 13:15:15 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-13 11:22:47 +0000 (Mon, 13 May 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-3123");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL < 5.6.43, < 5.7.25, < 8.0.14 Security Update (2019-5072813) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to a vulnerability in the libmysqld subcomponent.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Difficult to exploit vulnerability allows unauthenticated attacker with
  network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized access to critical data or complete access to all MySQL Server accessible data.");

  script_tag(name:"affected", value:"MySQL 5.6.42 and prior, 5.7.24 and prior, 8.0.13 and prior.");

  script_tag(name:"solution", value:"Update to version 5.6.43, 5.7.25, 8.0.14 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixMSQL");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "5.6.43")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.43", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.7", test_version2: "5.7.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.25", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.14", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
