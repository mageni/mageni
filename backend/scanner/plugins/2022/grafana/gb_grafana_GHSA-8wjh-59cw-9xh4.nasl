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
  script_oid("1.3.6.1.4.1.25623.1.0.147463");
  script_version("2022-01-19T02:06:52+0000");
  script_tag(name:"last_modification", value:"2022-01-19 11:07:58 +0000 (Wed, 19 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-19 02:00:20 +0000 (Wed, 19 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2022-21673");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana OAuth Identity Token Vulnerability (GHSA-8wjh-59cw-9xh4)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a vulnerability in the OAuth identity token.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When a data source has the Forward OAuth Identity feature
  enabled, sending a query to that datasource with an API token (and no other user credentials)
  will forward the OAuth Identity of the most recently logged-in user.

  This can allow API token holders to retrieve data for which they may not have intended access.

  All of the following must be true:

  - The Grafana instance has data sources that support the Forward OAuth Identity feature. Graphite
  users, for example.

  - The Grafana instance has a data source with the Forward OAuth Identity feature toggled on.

  - The Grafana instance has OAuth enabled.

  - The Grafana instance has usable API keys.");

  script_tag(name:"affected", value:"Grafana version 7.2 through 7.5.12 and 8.x through 8.3.3.");

  script_tag(name:"solution", value:"Update to version 7.5.13, 8.3.4 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-8wjh-59cw-9xh4");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.2", test_version_up: "7.5.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.5.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
