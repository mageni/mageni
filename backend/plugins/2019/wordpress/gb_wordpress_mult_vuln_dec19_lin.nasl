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
  script_oid("1.3.6.1.4.1.25623.1.0.112674");
  script_version("2019-12-16T14:43:37+0000");
  script_tag(name:"last_modification", value:"2019-12-16 14:43:37 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-16 13:38:14 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities - Dec19 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An issue where an unprivileged user could make a post sticky via the REST API

  - An issue where cross-site scripting (XSS) could be stored in well-crafted links

  - wp_kses_bad_protocol() is not aware of the named colon attribute

  - A stored XSS vulnerability using block editor content.");

  script_tag(name:"affected", value:"WordPress version 5.3.1 and earlier.");

  script_tag(name:"solution", value:"Update to version 3.7.31, 3.8.31, 3.9.29, 4.0.28, 4.1.28, 4.2.25, 4.3.21,
  4.4.20, 4.5.19, 4.6.16, 4.7.15, 4.8.11, 4.9.12, 5.0.7, 5.1.3, 5.2.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "3.7.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "3.8", test_version2: "3.8.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "3.9", test_version2: "3.9.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.0", test_version2: "4.0.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.1", test_version2: "4.1.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.2", test_version2: "4.2.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.3", test_version2: "4.3.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.4", test_version2: "4.4.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.5", test_version2: "4.5.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.6", test_version2: "4.6.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.7", test_version2: "4.7.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.8", test_version2: "4.8.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.9", test_version2: "4.9.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "5.0", test_version2: "5.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "5.1", test_version2: "5.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "5.2", test_version2: "5.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_is_equal(version: version, test_version: "5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
