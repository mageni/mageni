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
  script_oid("1.3.6.1.4.1.25623.1.0.127205");
  script_version("2022-09-26T10:10:50+0000");
  script_tag(name:"last_modification", value:"2022-09-26 10:10:50 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-23 08:24:40 +0000 (Fri, 23 Sep 2022)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:P");

  script_cve_id("CVE-2022-36062");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 8.5.0 < 8.5.13, 9.0.0 < 9.0.9, 9.1.0 < 9.1.6 Privilege escalation Vulnerability (GHSA-p978-56hq-r492)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a privilege escalation Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability impacts Grafana instances where RBAC was
  disabled and enabled afterwards, as the migrations which are translating legacy folder
  permissions to RBAC permissions do not account for the scenario where the only user permission in
  the folder is Admin, as a result RBAC adds permissions for Editors and Viewers which allow them
  to edit and view folders accordingly.");

  script_tag(name:"affected", value:"Grafana version 8.5.0 prior to 8.5.13, version 9.0.0 prior to
  9.0.9 and version 9.1.0 prior to 9.1.6.");

  script_tag(name:"solution", value:"Update to version 8.5.13, 9.0.9, 9.1.6 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-p978-56hq-r492");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.5.0", test_version_up: "8.5.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0", test_version_up: "9.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1.0", test_version_up: "9.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
