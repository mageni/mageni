# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142309");
  script_version("2019-04-26T11:51:03+0000");
  script_tag(name:"last_modification", value:"2019-04-26 11:51:03 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-25 12:50:07 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2019-10247");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Information Disclosure Vulnerability - CVE-2019-10247 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Jetty/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclypse Jetty is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"The DefaultHandler will present the full path to the Resource Base directory,
  if the server is configured with only non-root contexts.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty version 7.x and prior, 8.x, 9.2.27.v20190403 and prior,
  9.3.26.v20190403 and prior and 9.4.16.v20190411 and prior.");

  script_tag(name:"solution", value:"Update to version 9.2.28.v20190418, 9.3.27.v20190418, 9.4.17.v20190418 or
  later.");

  script_xref(name:"URL", value:"https://bugs.eclipse.org/bugs/show_bug.cgi?id=546577");
  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/issues/3555");

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

if (version_is_less(version: version, test_version: "9.2.28.20190418")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.28.20190418", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.3", test_version2: "9.3.26.20190403")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.27.20190418", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.4", test_version2: "9.4.16.20190411")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.17.20190418", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
