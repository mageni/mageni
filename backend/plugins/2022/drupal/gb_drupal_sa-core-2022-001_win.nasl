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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147489");
  script_version("2022-01-20T05:25:29+0000");
  script_tag(name:"last_modification", value:"2022-01-20 05:25:29 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-20 05:17:07 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-41183");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 8.x, 9.x < 9.2.11, 9.3.x < 9.3.3 XSS Vulnerability (SA-CORE-2022-001) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a cross-site scripting (XSS)
  vulnerability in jQuery UI.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"jQuery UI is a third-party library used by Drupal. This library
  was previously thought to be end-of-life.

  Late in 2021, jQuery UI announced that they would be continuing development, and released a
  jQuery UI 1.13.0 version.

  It is possible that this vulnerability is exploitable with some Drupal modules. As a precaution,
  this Drupal security release applies the fix for the above cross-site description issue, without
  making any of the other changes to the jQuery version that is included in Drupal.");

  script_tag(name:"affected", value:"Drupal version 8.x, 9.x through 9.2.10 and 9.3.x through 9.3.2.");

  script_tag(name:"solution", value:"Update to version 9.2.11, 9.3.3 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2022-001");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.0", test_version2: "9.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.3", test_version2: "9.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
