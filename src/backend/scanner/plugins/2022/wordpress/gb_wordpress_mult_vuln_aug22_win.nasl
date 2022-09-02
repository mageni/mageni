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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148653");
  script_version("2022-09-01T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-09-01 10:11:07 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-01 03:24:35 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (Aug 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - No CVE: SQL injection (SQLi) within the Link API

  - No CVE: Cross-site scripting (XSS) on the Plugins screen

  - No CVE: Output escaping issue within the_meta()");

  script_tag(name:"affected", value:"WordPress version 6.0.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.7.39, 3.8.39, 3.9.37, 4.0.36, 4.1.36,
  4.2.33, 4.3.29, 4.4.28, 4.5.27, 4.6.24, 4.7.24, 4.8.20, 4.9.21, 5.0.17, 5.1.14, 5.2.16, 5.3.13,
  5.4.11, 5.5.10, 5.6.9, 5.7.7, 5.8.5, 5.9.4, 6.0.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.7.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8", test_version_up: "3.8.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9", test_version_up: "3.9.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.0.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4", test_version_up: "4.4.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5", test_version_up: "4.5.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.6", test_version_up: "4.6.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.7", test_version_up: "4.7.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.8", test_version_up: "4.8.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9", test_version_up: "4.9.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3", test_version_up: "5.3.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4", test_version_up: "5.4.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5", test_version_up: "5.5.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6", test_version_up: "5.6.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.7", test_version_up: "5.7.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.8", test_version_up: "5.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.9", test_version_up: "5.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
