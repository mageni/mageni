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
  script_oid("1.3.6.1.4.1.25623.1.0.147396");
  script_version("2022-01-11T06:40:03+0000");
  script_tag(name:"last_modification", value:"2022-01-11 06:40:03 +0000 (Tue, 11 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-11 06:11:52 +0000 (Tue, 11 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-21661", "CVE-2022-21662", "CVE-2022-21663", "CVE-2022-21664");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (Jan 2022) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-21661: SQL injection (SQLi) through WP_Query

  - CVE-2022-21662: Stored XSS through authenticated users

  - CVE-2022-21663: Authenticated object injection in multisites

  - CVE-2022-21664: SQL injection (SQLi) due to improper sanitization in WP_Meta_Query");

  script_tag(name:"affected", value:"WordPress version 5.8.2 and prior.");

  script_tag(name:"solution", value:"Update to version 3.7.37, 3.8.37, 3.9.35, 4.0.34, 4.1.34,
  4.2.31, 4.3.27, 4.4.26, 4.5.25, 4.6.22, 4.7.22, 4.8.18, 4.9.19, 5.0.15, 5.1.12, 5.2.14, 5.3.11,
  5.4.9, 5.5.8, 5.6.7, 5.7.5, 5.8.3 or later.");

  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84");
  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w");
  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h");
  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86");

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

if (version_is_less(version: version, test_version: "3.7.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8", test_version_up: "3.8.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9", test_version_up: "3.9.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.0.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4", test_version_up: "4.4.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5", test_version_up: "4.5.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.6", test_version_up: "4.6.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.7", test_version_up: "4.7.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.8", test_version_up: "4.8.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9", test_version_up: "4.9.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3", test_version_up: "5.3.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4", test_version_up: "5.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5", test_version_up: "5.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6", test_version_up: "5.6.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.7", test_version_up: "5.7.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.8", test_version_up: "5.8.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
