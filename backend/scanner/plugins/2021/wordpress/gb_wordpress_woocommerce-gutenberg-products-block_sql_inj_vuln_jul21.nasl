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

CPE = "cpe:/a:claudiulodro:woocommerce_blocks";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112910");
  script_version("2021-07-16T12:10:35+0000");
  script_tag(name:"last_modification", value:"2021-07-19 10:21:49 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-16 11:00:00 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooCommerce Blocks Plugin SQL Injection Vulnerability (Jul 2021)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woo-gutenberg-products-block/detected");

  script_tag(name:"summary", value:"The WooCommerce Blocks plugin for WordPress is prone to an SQL
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows unauthenticated attackers to access
  arbitrary data in an online store's database.");

  script_tag(name:"affected", value:"The vulnerability affects versions 2.5 to 5.5.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced advisory
  for more information.");

  script_xref(name:"URL", value:"https://woocommerce.com/posts/critical-vulnerability-detected-july-2021/#");

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

if (version_is_less(version: version, test_version: "2.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.6.0", test_version2: "2.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.7.0", test_version2: "2.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "2.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "2.9.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.7.0", test_version2: "3.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.9.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.0", test_version2: "4.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5.0", test_version2: "4.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}
if (version_is_equal(version: version, test_version: "4.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.9.0", test_version2: "4.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3.0", test_version2: "5.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
