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
  script_oid("1.3.6.1.4.1.25623.1.0.142131");
  script_version("2019-04-12T12:22:59+0000");
  script_tag(name:"last_modification", value:"2019-04-12 12:22:59 +0000 (Fri, 12 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-12 09:48:02 +0700 (Tue, 12 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-9637", "CVE-2019-9638", "CVE-2019-9639", "CVE-2019-9640", "CVE-2019-9641");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities - Mar19 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHP is prone to multiple vulnerabilities:

  - Due to the way rename() across filesystems is implemented, it is possible that file being renamed is briefly
    available with wrong permissions while the rename is ongoing, thus enabling unauthorized users to access the
    data. (CVE-2019-9637)

  - Uninitialized read in exif_process_IFD_in_MAKERNOTE because of mishandling the maker_note->offset
    relationship to value_len (CVE-2019-9638)

  - Uninitialized read in exif_process_IFD_in_MAKERNOTE because of mishandling the data_len variable
    (CVE-2019-9639)

  - Invalid Read in exif_process_SOFn (CVE-2019-9640)

  - Uninitialized read in exif_process_IFD_in_TIFF (CVE-2019-9641)");

  script_tag(name:"affected", value:"PHP version 7.x before 7.1.27, 7.2.x before 7.2.16 and 7.3.x before 7.3.3.");

  script_tag(name:"solution", value:"Update to version 7.1.27, 7.2.16, 7.3.3 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77630");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77563");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77659");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77540");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77509");

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

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.1.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.27", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.2", test_version2: "7.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.16", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.3", test_version2: "7.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
