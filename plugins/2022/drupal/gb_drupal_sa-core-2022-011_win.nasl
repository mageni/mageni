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
  script_oid("1.3.6.1.4.1.25623.1.0.148292");
  script_version("2022-06-16T04:41:03+0000");
  script_tag(name:"last_modification", value:"2022-06-16 04:41:03 +0000 (Thu, 16 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-16 04:40:19 +0000 (Thu, 16 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2022-31042", "CVE-2022-31043");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Third-party Library Information Disclosure Vulnerabilities (SA-CORE-2022-011) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities in the third-party
  Guzzle library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal uses the third-party Guzzle library for handling HTTP
  requests and responses to external services. Guzzle has released two security advisories:

  - Failure to strip the Cookie header on change in host or HTTP downgrade

  - Fix failure to strip Authorization header on HTTP downgrade

  These do not affect Drupal core, but may affect some contributed projects or custom code on
  Drupal sites.");

  script_tag(name:"affected", value:"Drupal versions 9.x through 9.2.21 and 9.3.x through 9.3.15.
  Drupal 7 is not affected.");

  script_tag(name:"solution", value:"Update to version 9.2.21, 9.3.16 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2022-011");
  script_xref(name:"URL", value:"https://github.com/guzzle/guzzle/security/advisories/GHSA-f2wf-25xc-69c9");
  script_xref(name:"URL", value:"https://github.com/guzzle/guzzle/security/advisories/GHSA-w248-ffj2-4v5q");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.2.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
