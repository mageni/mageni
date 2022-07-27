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

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142695");
  script_version("2019-08-05T08:30:28+0000");
  script_tag(name:"last_modification", value:"2019-08-05 08:30:28 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-05 08:23:13 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-11041", "CVE-2019-11042");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities - Aug19 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple heap-based buffer overflows vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHP is prone to multiple vulnerabilities:

  - Heap-buffer-overflow on exif_scan_thumbnail (CVE-2019-11041)

  - Heap-buffer-overflow on exif_process_user_comment (CVE-2019-11042)");

  script_tag(name:"affected", value:"PHP version 7.x before 7.1.31, 7.2.x before 7.2.21 and 7.3.x before 7.3.8.");

  script_tag(name:"solution", value:"Update to version 7.1.31, 7.2.21, 7.3.8 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=78256");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=78222");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.1.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.31", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.2", test_version2: "7.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.21", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.3", test_version2: "7.3.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.8", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
