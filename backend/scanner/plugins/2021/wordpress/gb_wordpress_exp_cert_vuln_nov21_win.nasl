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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147139");
  script_version("2021-11-12T03:15:47+0000");
  script_tag(name:"last_modification", value:"2021-11-12 11:32:18 +0000 (Fri, 12 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-12 03:14:57 +0000 (Fri, 12 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Expired Root CA Vulnerability (Nov 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress contains an expired root CA.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress versions 5.2 through 5.8.");

  script_tag(name:"solution", value:"Update to version 5.2.13, 5.3.10, 5.4.8, 5.5.7, 5.6.6, 5.7.4,
  5.8.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/");

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

if (version_in_range(version: version, test_version: "5.2", test_version2: "5.2.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3", test_version2: "5.3.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4", test_version2: "5.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5", test_version2: "5.5.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.6", test_version2: "5.6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.7", test_version2: "5.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.8.0", test_version2: "5.8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
