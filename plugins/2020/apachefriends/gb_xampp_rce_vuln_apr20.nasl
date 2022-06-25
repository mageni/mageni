# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:apachefriends:xampp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143676");
  script_version("2020-04-06T07:45:06+0000");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-06 07:09:31 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-11107");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XAMPP < 7.2.29, 7.3 < 7.3.16, 7.4 < 7.4.4 Configuration Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xampp_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("xampp/installed", "Host/runs_windows");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"XAMPP for Windows is prone to a vulnerability where an unprivileged user can
  change a .exe configuration in xampp-contol.ini for all users (including admins) to enable arbitrary command
  execution.");

  script_tag(name:"affected", value:"XAMPP for Windows versions prior 7.2.29, 7.3.x prior 7.3.16 and 7.4.x prior 7.4.4.");

  script_tag(name:"solution", value:"Update to version 7.2.29, 7.3.16, 7.4.4 or later.");

  script_xref(name:"URL", value:"https://www.apachefriends.org/blog/new_xampp_20200401.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "7.2.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.3.0", test_version2: "7.3.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.4.0", test_version2: "7.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
