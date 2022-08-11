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
  script_oid("1.3.6.1.4.1.25623.1.0.142386");
  script_version("2019-05-14T07:15:16+0000");
  script_tag(name:"last_modification", value:"2019-05-14 07:15:16 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-09 09:46:02 +0000 (Thu, 09 May 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-11831");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Third-party Libraries Vulnerability (SA-CORE-2019-007) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a vulnerability in the 3rd party library Phar Stream Wrapper.");

  script_tag(name:"insight", value:"The vulnerability lies in third-party dependencies included in or required by
  Drupal core. As described in TYPO3-PSA-2019-007 (By-passing protection of Phar Stream Wrapper Interceptor).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Drupal 7.x, 8.6.x or earlier and 8.7.0.");

  script_tag(name:"solution", value:"Update to version 7.67, 8.6.16, 8.7.1 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-007");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-psa-2019-007/");

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

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.66")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.67", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.6.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.16", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
