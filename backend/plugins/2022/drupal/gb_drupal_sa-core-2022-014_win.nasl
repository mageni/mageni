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
  script_oid("1.3.6.1.4.1.25623.1.0.148533");
  script_version("2022-07-25T06:58:42+0000");
  script_tag(name:"last_modification", value:"2022-07-25 06:58:42 +0000 (Mon, 25 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-25 06:50:05 +0000 (Mon, 25 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2022-25277");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal RCE Vulnerability (SA-CORE-2022-014) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal core sanitizes filenames with dangerous extensions upon
  upload (reference: SA-CORE-2020-012) and strips leading and trailing dots from filenames to
  prevent uploading server configuration files (reference: SA-CORE-2019-010).

  However, the protections for these two vulnerabilities previously did not work correctly
  together. As a result, if the site were configured to allow the upload of files with an htaccess
  extension, these files' filenames would not be properly sanitized. This could allow bypassing the
  protections provided by Drupal core's default .htaccess files and possible remote code execution
  on Apache web servers.

  This issue is mitigated by the fact that it requires a field administrator to explicitly
  configure a file field to allow htaccess as an extension (a restricted permission), or a
  contributed module or custom code that overrides allowed file uploads.");

  script_tag(name:"affected", value:"Drupal versions 9.x through 9.3.18 and 9.4.x through 9.4.2.");

  script_tag(name:"solution", value:"Update to version 9.3.19, 9.4.3 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2022-014");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.3.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.4", test_version_up: "9.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
