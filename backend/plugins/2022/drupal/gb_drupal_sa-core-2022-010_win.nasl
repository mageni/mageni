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
  script_oid("1.3.6.1.4.1.25623.1.0.104232");
  script_version("2022-05-31T13:00:51+0000");
  script_tag(name:"last_modification", value:"2022-06-01 10:00:47 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-05-31 12:36:59 +0000 (Tue, 31 May 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-29248");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Third-party Library Information Disclosure Vulnerability (SA-CORE-2022-010) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a information disclosure vulnerability in the
  third-party Guzzle library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal uses the third-party Guzzle library for handling HTTP
  requests and responses to external services. Guzzle has released a security update which does not
  affect Drupal core, but may affect some contributed projects or custom code on Drupal sites.

  Previous version of Guzzle contain a vulnerability with the cookie middleware. The vulnerability
  is that it is not checked if the cookie domain equals the domain of the server which sets the
  cookie via the Set-Cookie header, allowing a malicious server to set cookies for unrelated
  domains. For example an attacker at www.example.com might set a session cookie for
  api.example.net, logging the Guzzle client into their account and retrieving private API requests
  from the security log of their account.");

  script_tag(name:"affected", value:"Drupal versions 8.x through 9.2.19 and 9.3.x prior to
  9.3.14. Drupal 7 is not affected.");

  script_tag(name:"solution", value:"Update to version 9.2.20, 9.3.14 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2022-010");
  script_xref(name:"URL", value:"https://github.com/guzzle/guzzle/security/advisories/GHSA-cwmx-hcrq-mhc3");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "9.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
