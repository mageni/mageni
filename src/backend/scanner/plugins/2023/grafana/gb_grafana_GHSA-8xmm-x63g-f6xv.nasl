# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.149214");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-30 07:13:12 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2022-23552");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 8.1.0 < 9.2.10, 9.3.0 < 9.3.4 XSS Vulnerability (GHSA-8xmm-x63g-f6xv)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a stored cross-site scripting (XSS)
  vulnerability in the ResourcePicker component.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stored XSS vulnerability is possible due to SVG-files aren't
  properly sanitized and allow arbitrary JavaScript to be executed in the context of the currently
  authorized user of the Grafana instance.");

  script_tag(name:"impact", value:"An attacker needs to have the Editor role in order to change a
  panel to include either an external URL to a SVG-file containing JavaScript, or use the data:
  scheme to load an inline SVG-file containing JavaScript. This means that vertical privilege
  escalation is possible, where a user with Editor role can change to a known password for a user
  having Admin role if the user with Admin role executes malicious JavaScript viewing a dashboard.");

  script_tag(name:"affected", value:"Grafana version 8.1.0 through 9.2.9 and version 9.3.0 through
  9.3.3.");

  script_tag(name:"solution", value:"Update to version 9.2.10, 9.3.4 or later.");

  script_xref(name:"URL", value:"https://grafana.com/blog/2023/01/25/grafana-security-releases-new-versions-with-fixes-for-cve-2022-23552-cve-2022-41912-and-cve-2022-39324/");
  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-8xmm-x63g-f6xv");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.1.0", test_version_up: "9.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3.0", test_version_up: "9.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
