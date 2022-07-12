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
  script_oid("1.3.6.1.4.1.25623.1.0.147338");
  script_version("2021-12-16T10:21:14+0000");
  script_tag(name:"last_modification", value:"2021-12-16 11:53:28 +0000 (Thu, 16 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-16 04:18:53 +0000 (Thu, 16 Dec 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 19:06:00 +0000 (Tue, 14 Dec 2021)");

  script_cve_id("CVE-2021-43815");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 8.0.0-beta3 - 8.3.1 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a directory traversal vulnerability for
  '.csv' files.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Grafana has a directory traversal for arbitrary .csv files. It
  only affects instances that have the developer testing tool called TestData DB data source
  enabled and configured. The vulnerability is limited in scope, and only allows access to files
  with the extension .csv to authenticated users only.");

  script_tag(name:"affected", value:"Grafana version 8.0.0-beta3 through 8.3.1.");

  script_tag(name:"solution", value:"Update to version 8.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-7533-c8qv-jm9m");

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

if (version_in_range(version: version, test_version: "8.0.0-beta3", test_version2: "8.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
