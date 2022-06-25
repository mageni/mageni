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
  script_oid("1.3.6.1.4.1.25623.1.0.145114");
  script_version("2021-01-11T08:25:20+0000");
  script_tag(name:"last_modification", value:"2021-01-11 11:04:52 +0000 (Mon, 11 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-11 08:15:33 +0000 (Mon, 11 Jan 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-7071");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 7.3.26, 7.4 < 7.4.14, 8.0 < 8.0.1 Filter Vulnerability - January21 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to a vulnerability where FILTER_VALIDATE_URL accepts URLs
  with invalid userinfo.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PHP versions prior to 7.3.26, 7.4 prior to 7.4.14 and 8.0 prior to 8.0.1.");

  script_tag(name:"solution", value:"Update to version 7.3.26, 7.4.14, 8.0.1 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.26");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.4.14");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.1");

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

if (version_is_less(version: version, test_version: "7.3.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);

}

if (version_in_range(version: version, test_version: "7.4.0", test_version2: "7.4.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "8.0.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
