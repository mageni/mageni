# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142301");
  script_version("2019-04-24T09:29:51+0000");
  script_tag(name:"last_modification", value:"2019-04-24 09:29:51 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-24 09:25:05 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-11358");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal jQuery XSS Vulnerability (SA-CORE-2019-006) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a cross-site scripting vulnerability in jQuery.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"jQuery 3.4.0 includes a fix for some unintended behavior when using
  jQuery.extend(true, {}, ...). If an unsanitized source object contained an enumerable __proto__ property, it
  could extend the native Object.prototype. This fix is included in jQuery 3.4.0, but patch diffs exist to patch
  previous jQuery versions.");

  script_tag(name:"affected", value:"Drupal 7, 8.5.x or earlier and 8.6.x.");

  script_tag(name:"solution", value:"Update to version 7.66, 8.5.15, 8.6.15 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-006");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.65")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.66", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.15", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.6", test_version2: "8.6.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.15", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
