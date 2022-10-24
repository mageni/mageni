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
  script_oid("1.3.6.1.4.1.25623.1.0.170196");
  script_version("2022-10-20T10:12:23+0000");
  script_tag(name:"last_modification", value:"2022-10-20 10:12:23 +0000 (Thu, 20 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-19 19:58:44 +0000 (Wed, 19 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (Oct 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - No CVE: Stored cross-site scripting (XSS) via wp-mail.php (post by email)

  - No CVE: Open redirect in `wp_nonce_ays`

  - No CVE: Sender's email address is exposed in wp-mail.php

  - No CVE: Reflected XSS via SQL injection (SQLi) in Media Library

  - No CVE: Cross-site request forgery (CSRF) in wp-trackback.php

  - No CVE: Stored XSS via the Customizer

  - No CVE: Revert shared user instances introduced in 50790

  - No CVE: Stored XSS in WordPress Core via comment editing

  - No CVE: Data exposure via the REST Terms/Tags endpoint

  - No CVE: Content from multipart emails leaked

  - No CVE: SQL injection (SQLi) due to improper sanitization in `WP_Date_Query`

  - No CVE: Stored XSS in the RSS Widget

  - No CVE: Stored XSS in the search block

  - No CVE: XSS in the Feature Image Block

  - No CVE: Stored XSS in the RSS Block

  - No CVE: Fix widget block XSS");

  script_tag(name:"affected", value:"WordPress version 6.0.2 and prior.");

  script_tag(name:"solution", value:"Update to version 3.7.40, 3.8.40, 3.9.39, 4.0.37, 4.1.37,
  4.2.34, 4.3.30, 4.4.29, 4.5.28, 4.6.25, 4.7.25, 4.8.21, 4.9.22, 5.0.18, 5.1.15, 5.2.17, 5.3.14,
  5.4.12, 5.5.11, 5.6.10, 5.7.8, 5.8.6, 5.9.5, 6.0.3 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/");

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

if (version_is_less(version: version, test_version: "3.7.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.40", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8", test_version_up: "3.8.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.40", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9", test_version_up: "3.9.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.0.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4", test_version_up: "4.4.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5", test_version_up: "4.5.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.6", test_version_up: "4.6.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.7", test_version_up: "4.7.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.8", test_version_up: "4.8.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9", test_version_up: "4.9.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3", test_version_up: "5.3.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4", test_version_up: "5.4.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5", test_version_up: "5.5.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6", test_version_up: "5.6.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.7", test_version_up: "5.7.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.8", test_version_up: "5.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.9", test_version_up: "5.9.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
