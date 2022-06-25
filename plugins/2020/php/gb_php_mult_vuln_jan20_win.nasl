# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143393");
  script_version("2020-01-24T06:13:01+0000");
  script_tag(name:"last_modification", value:"2020-01-24 06:13:01 +0000 (Fri, 24 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-24 06:12:06 +0000 (Fri, 24 Jan 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-7059", "CVE-2020-7060");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 7.2.27, 7.3.x < 7.3.14, 7.4.x < 7.4.2 Multiple Vulnerabilities - Jan20 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHP is prone to multiple vulnerabilities:

  - OOB read in php_strip_tags_ex (CVE-2020-7059)

  - Global buffer-overflow in 'mbfl_filt_conv_big5_wchar' (CVE-2020-7060)");

  script_tag(name:"affected", value:"PHP versions before 7.2.27, 7.3.x and 7.4.x.");

  script_tag(name:"solution", value:"Update to version 7.2.27, 7.3.14, 7.4.2 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.2.27");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.14");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.4.2");

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

if (version_is_less(version: version, test_version: "7.2.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.3.0", test_version2: "7.3.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.4.0", test_version2: "7.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
