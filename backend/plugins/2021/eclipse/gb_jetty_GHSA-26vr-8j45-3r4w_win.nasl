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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117488");
  script_version("2021-06-09T14:18:22+0000");
  script_tag(name:"last_modification", value:"2021-06-10 10:19:24 +0000 (Thu, 10 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-09 14:02:30 +0000 (Wed, 09 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2021-28165");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty DoS Vulnerability (GHSA-26vr-8j45-3r4w) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"impact", value:"When using SSL/TLS with Jetty, either with HTTP/1.1, HTTP/2, or
  WebSocket, the server may receive an invalid large (greater than 17408) TLS frame that is
  incorrectly handled, causing CPU resources to eventually reach 100% usage.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty version 7.2.2 through 9.4.38, 10.0.0.alpha0
  through 10.0.1 and 11.0.0.alpha0 through 11.0.1.");

  script_tag(name:"solution", value:"Update to version 9.4.39, 10.0.2, 11.0.2 or later. See the
  referenced vendor advisory for a possible mitigation.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-26vr-8j45-3r4w");

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

if (version_in_range(version: version, test_version: "7.2.2", test_version2: "9.4.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0.0", test_version2: "10.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.0", test_version2: "11.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);