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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147272");
  script_version("2021-12-08T06:13:33+0000");
  script_tag(name:"last_modification", value:"2021-12-09 11:40:32 +0000 (Thu, 09 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-08 06:10:25 +0000 (Wed, 08 Dec 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2021-43798");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 8.0.0-beta1 - 8.3.0 Directory Traversal Vulnerability - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Grafana is vulnerable to directory traversal, allowing access
  to local files. The vulnerable URL path is: <grafana_host_url>/public/plugins/<'plugin-id'> where
  <'plugin-id'> is the plugin ID for any installed plugin.

  Every Grafana instance comes with pre-installed plugins like the Prometheus plugin or MySQL plugin
  so multiple URLs are vulnerable for every instance.");

  script_tag(name:"impact", value:"An unauthenticated attacker may read arbitrary files.");

  script_tag(name:"affected", value:"Grafana version 8.0.0-beta1 through 8.3.0.");

  script_tag(name:"solution", value:"Update to version 8.0.7, 8.1.8, 8.2.7, 8.3.1 or later.");

  script_xref(name:"URL", value:"https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.1", test_version2: "8.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.2", test_version2: "8.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
