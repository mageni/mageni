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
  script_oid("1.3.6.1.4.1.25623.1.0.144102");
  script_version("2020-06-15T04:38:38+0000");
  script_tag(name:"last_modification", value:"2020-06-15 12:06:35 +0000 (Mon, 15 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-15 02:23:35 +0000 (Mon, 15 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:N");

  script_cve_id("CVE-2020-4047", "CVE-2020-4048", "CVE-2020-4049", "CVE-2020-4050");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities - June20 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WordPress is prone to multiple vulnerabilities:

  - Authenticated users with upload permissions (like authors) are able to inject JavaScript into some media
    file attachment pages in a certain way. This can lead to script execution in the context of a higher
    privileged user when the file is viewed by them. (CVE-2020-4047)

  - Due to an issue in wp_validate_redirect() and URL sanitization, an arbitrary external link can be crafted
    leading to unintended/open redirect when clicked. (CVE-2020-4048)

  - When uploading themes, the name of the theme folder can be crafted in a way that could lead to JavaScript
    execution in /wp-admin on the themes page. This does require an admin to upload the theme, and is low
    severity self-XSS. (CVE-2020-4049)

  - Misuse of the 'set-screen-option' filter's return value allows arbitrary user meta fields to be saved. It
    does require an admin to install a plugin that would misuse the filter. Once installed, it can be leveraged
    by low privileged users. (CVE-2020-4050)");

  script_tag(name:"affected", value:"WordPress versions 3.7 - 5.4.1.");

  script_tag(name:"solution", value:"Update to version 3.7.34, 3.8.34, 3.9.32, 4.0.31, 4.1.31, 4.2.28, 4.3.24,
  4.4.23, 4.5.22, 4.6.19, 4.7.18, 4.8.14, 4.9.15, 5.0.10, 5.1.6, 5.2.7, 5.3.4, 5.4.2 or later.");

  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8q2w-5m27-wm27");
  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-q6pw-gvf4-5fj5");
  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-87h4-phjv-rm6p");
  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4vpv-fgg2-gcqc");

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

if (version_in_range(version: version, test_version: "3.7", test_version2: "3.7.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8", test_version2: "3.8.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.9", test_version2: "3.9.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2", test_version2: "4.2.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3", test_version2: "4.3.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4", test_version2: "4.4.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5", test_version2: "4.5.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.6", test_version2: "4.6.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.7", test_version2: "4.7.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.8", test_version2: "4.8.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.9", test_version2: "4.9.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.1", test_version2: "5.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2", test_version2: "5.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3", test_version2: "5.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4", test_version2: "5.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
