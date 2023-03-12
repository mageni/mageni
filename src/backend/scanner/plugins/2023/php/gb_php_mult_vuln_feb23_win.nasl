# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104542");
  script_version("2023-02-16T10:08:32+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:08:32 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-15 13:46:36 +0000 (Wed, 15 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-0567", "CVE-2023-0568", "CVE-2023-0662");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.0.28, 8.1.x < 8.1.16, 8.2.x < 8.2.3 Security Update - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-0567: Fixed bug #81744 (Password_verify() always return true with some hash)

  - CVE-2023-0568: Fixed bug #81746 (1-byte array overrun in common path resolve code)

  - CVE-2023-0662: Fixed bug GHSA-54hq-v5wp-fqgv (DOS vulnerability when parsing multipart request
  body)");

  script_tag(name:"affected", value:"PHP versions prior to 8.0.28, 8.1.x prior to 8.1.16 and
  8.2.x prior to 8.2.3.");

  script_tag(name:"solution", value:"Update to version 8.0.28, 8.1.16, 8.2.3 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.3");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.16");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.28");
  script_xref(name:"URL", value:"https://www.php.net/archive/2023.php#2023-02-14-2");
  script_xref(name:"URL", value:"https://www.php.net/archive/2023.php#2023-02-14-3");
  script_xref(name:"URL", value:"https://www.php.net/archive/2023.php#2023-02-14-1");
  script_xref(name:"URL", value:"http://bugs.php.net/81744");
  script_xref(name:"URL", value:"http://bugs.php.net/81746");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-54hq-v5wp-fqgv");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-7fj2-8x79-rjf4");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.0.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.1", test_version_up: "8.1.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
