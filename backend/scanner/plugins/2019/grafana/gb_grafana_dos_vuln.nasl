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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142855");
  script_version("2019-09-06T04:34:33+0000");
  script_tag(name:"last_modification", value:"2019-09-06 04:34:33 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-06 04:24:45 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-15043");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 2.0.0 < 5.4.5, 6.x < 6.3.4 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Parts of the HTTP API allow unauthenticated use. This makes it possible to run
  a denial of service attack against a server running Grafana.");

  script_tag(name:"affected", value:"Grafana versions 2.0.0 to 6.3.3.");

  script_tag(name:"solution", value:"Update to version 5.4.5, 6.3.4 or later.");

  script_xref(name:"URL", value:"https://community.grafana.com/t/grafana-5-4-5-and-6-3-4-security-update/20569");
  script_xref(name:"URL", value:"https://grafana.com/blog/2019/08/29/grafana-5.4.5-and-6.3.4-released-with-important-security-fix/");

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

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "5.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0", test_version2: "6.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
