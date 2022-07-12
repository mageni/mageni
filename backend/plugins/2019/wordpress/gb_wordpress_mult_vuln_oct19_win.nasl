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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143061");
  script_version("2019-10-28T01:43:34+0000");
  script_tag(name:"last_modification", value:"2019-10-28 01:43:34 +0000 (Mon, 28 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-25 09:10:14 +0000 (Fri, 25 Oct 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-17669", "CVE-2019-17670", "CVE-2019-17671", "CVE-2019-17672", "CVE-2019-17673",
                "CVE-2019-17674", "CVE-2019-17675");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities - Oct19 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Wordpress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Wordpress is prone to multiple vulnerabilities:

  - Stored XSS via the Customizer

  - Possibility to view unauthenticated posts

  - Stored XSS to inject Javascript into style tags

  - Cache poisoning of JSON GET requests via the Vary: Origin header

  - Server-Side Request Forgery in URL validation

  - Issues in referrer validation in the admin");

  script_tag(name:"affected", value:"WordPress version 5.2.3 and earlier.");

  script_tag(name:"solution", value:"Update to version 3.7.31, 3.8.31, 3.9.29, 4.0.28, 4.1.28, 4.2.25, 4.3.21,
  4.4.20, 4.5.19, 4.6.16, 4.7.15, 4.8.11, 4.9.12, 5.0.7, 5.1.3, 5.2.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/");

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

if (version_is_less(version: version, test_version: "3.7.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8", test_version2: "3.8.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.9", test_version2: "3.9.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2", test_version2: "4.2.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3", test_version2: "4.3.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4", test_version2: "4.4.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5", test_version2: "4.5.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.6", test_version2: "4.6.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.7", test_version2: "4.7.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.8", test_version2: "4.8.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.9", test_version2: "4.9.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.1", test_version2: "5.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2", test_version2: "5.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
