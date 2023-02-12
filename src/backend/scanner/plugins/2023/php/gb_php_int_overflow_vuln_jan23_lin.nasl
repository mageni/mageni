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

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149069");
  script_version("2023-01-09T10:12:48+0000");
  script_tag(name:"last_modification", value:"2023-01-09 10:12:48 +0000 (Mon, 09 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-06 04:07:31 +0000 (Fri, 06 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-31631");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.0.27, 8.1.x < 8.1.14, 8.2.x < 8.2.1 Security Update - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to an integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to an uncaught integer overflow, PDO::quote() of PDO_SQLite
  may return a not properly quoted string.");

  script_tag(name:"affected", value:"PHP prior to version 8.0.27, version 8.1.x through 8.1.13 and
  8.2.0.");

  script_tag(name:"solution", value:"Update to version 8.0.27, 8.1.14, 8.2.1 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.27");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.14");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.1");

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

if (version_is_less(version: version, test_version: "8.0.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.1", test_version_up: "8.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
