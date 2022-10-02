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
  script_oid("1.3.6.1.4.1.25623.1.0.104336");
  script_version("2022-09-30T10:11:44+0000");
  script_tag(name:"last_modification", value:"2022-09-30 10:11:44 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-29 11:33:30 +0000 (Thu, 29 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:N");

  script_cve_id("CVE-2022-39261");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Multiple Vulnerabilities (SA-CORE-2022-016) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal uses the Twig third-party library for content templating
  and sanitization. Twig has released a security update that affects Drupal. Twig has rated the
  vulnerability as high severity.

  Drupal core's code extending Twig has also been updated to mitigate a related vulnerability.

  Multiple vulnerabilities are possible if an untrusted user has access to write Twig code,
  including potential unauthorized read access to private files, the contents of other files on the
  server, or database credentials.

  The vulnerability is mitigated by the fact that an exploit is only possible in Drupal core with a
  restricted access administrative permission. Additional exploit paths for the same vulnerability
  may exist with contributed or custom code that allows users to write Twig templates.");

  script_tag(name:"affected", value:"Drupal versions starting from 8.x and prior to 9.3.22, 9.4.x
  prior to 9.4.7.");

  script_tag(name:"solution", value:"Update to version 9.3.22, 9.4.7 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2022-016");
  script_xref(name:"URL", value:"https://symfony.com/blog/twig-security-release-possibility-to-load-a-template-outside-a-configured-directory-when-using-the-filesystem-loader");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "9.3.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.4", test_version_up: "9.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
