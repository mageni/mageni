# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.148743");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-22 02:31:17 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2022-35957");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana Privilege Escalation Vulnerability (GHSA-ff5c-938w-8c9q)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Grafana allows an escalation from Admin privileges to Server
  Admin when Auth proxy authentication is used.

  Auth proxy allows to authenticate a user by only providing the username (or email) in a
  X-WEBAUTH-USER HTTP header: the trust assumption is that a front proxy will take care of
  authentication and that Grafana server is publicly reachable only with this front proxy.

  Datasource proxy breaks this assumption:

  - it is possible to configure a fake datasource pointing to a localhost Grafana install with a
  X-WEBAUTH-USER HTTP header containing admin username.

  - This fake datasource can be called publicly via this proxying feature.");

  script_tag(name:"affected", value:"Grafana prior to version 8.5.13, version 9.0.x through 9.0.8
  and 9.1.x through 9.1.5 if the Auth Proxy is used.");

  script_tag(name:"solution", value:"Update to version 8.5.13, 9.0.9, 9.1.6 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-ff5c-938w-8c9q");

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

if (version_is_less(version: version, test_version: "8.5.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1", test_version_up: "9.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
