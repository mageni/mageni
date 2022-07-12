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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145811");
  script_version("2021-04-22T06:54:20+0000");
  script_tag(name:"last_modification", value:"2021-04-22 10:14:47 +0000 (Thu, 22 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-22 06:53:52 +0000 (Thu, 22 Apr 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 7.x, 8.x, 9.x XSS Vulnerability (SA-CORE-2021-002) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal core's sanitization API fails to properly filter XSS
  under certain circumstances.

  Note: Not all sites and users are affected, but configuration changes to prevent the exploit
  might be impractical and will vary between sites.");

  script_tag(name:"affected", value:"Drupal 7.x, 8.x, 9.0.x and 9.1.x.");

  script_tag(name:"solution", value:"Update to version 7.80, 8.9.14, 9.0.12, 9.1.7 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-002");

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

if (version_is_less(version: version, test_version: "7.80")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.80", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.9.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1", test_version2: "9.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
