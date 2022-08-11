# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117694");
  script_version("2021-09-27T06:13:32+0000");
  script_tag(name:"last_modification", value:"2021-09-27 10:21:48 +0000 (Mon, 27 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-27 05:54:48 +0000 (Mon, 27 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2021-21706");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 7.3.31, 7.4.x < 7.4.24, 8.0.x < 8.0.11 Security Update (Sep 2021) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP released new versions which includes a security fix.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Fixed bug #81420 (ZipArchive::extractTo extracts outside of
  destination).");

  script_tag(name:"affected", value:"PHP versions prior to 7.3.31, 7.4.x through 7.4.23 and 8.0.x
  through 8.0.10.");

  script_tag(name:"solution", value:"Update to version 7.3.31, 7.4.24, 8.0.11 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.31");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.4.24");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.11");
  script_xref(name:"URL", value:"http://bugs.php.net/81420");

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

if (version_is_less(version: version, test_version: "7.3.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.4", test_version2: "7.4.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);