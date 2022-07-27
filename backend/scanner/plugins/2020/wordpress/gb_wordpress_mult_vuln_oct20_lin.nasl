# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.144872");
  script_version("2020-11-02T05:01:06+0000");
  script_tag(name:"last_modification", value:"2020-11-02 14:55:55 +0000 (Mon, 02 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-02 04:37:32 +0000 (Mon, 02 Nov 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities - Oct20 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Multiple cross-site scripting

  - Privilege escalation in XML-RPC

  - DoS attack which could lead to a remote code execution

  - Arbitrary file deletion

  - Cross request forgery (CSRF)");

  script_tag(name:"affected", value:"All supported WordPress versions 3.7 - 5.5.1. Older versions might
  be affected as well.");

  script_tag(name:"solution", value:"Update to version 3.7.35, 3.8.35, 3.9.33, 4.0.32, 4.1.32, 4.2.29, 4.3.25,
  4.4.24, 4.5.23, 4.6.20, 4.7.19, 4.8.15, 4.9.16, 5.0.11, 5.1.7, 5.2.8, 5.3.5, 5.4.3, 5.5.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/");

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

if (version_is_less(version: version, test_version: "3.7.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8", test_version2: "3.8.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.9", test_version2: "3.9.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2", test_version2: "4.2.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3", test_version2: "4.3.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4", test_version2: "4.4.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5", test_version2: "4.5.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.6", test_version2: "4.6.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.7", test_version2: "4.7.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.8", test_version2: "4.8.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.9", test_version2: "4.9.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.1", test_version2: "5.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2", test_version2: "5.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3", test_version2: "5.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4", test_version2: "5.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5", test_version2: "5.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
