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

CPE = "cpe:/a:lucee:lucee_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146115");
  script_version("2021-06-11T10:00:57+0000");
  script_tag(name:"last_modification", value:"2021-06-14 10:28:51 +0000 (Mon, 14 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-11 09:21:00 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-21307");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lucee < 5.3.5.96, 5.3.6.x < 5.3.6.68, 5.3.7.x < 5.3.7.47 RCE Vulnerability (GHSA-2xvv-723c-8p7r) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_lucee_http_detect.nasl");
  script_mandatory_keys("lucee/detected");

  script_tag(name:"summary", value:"Lucee is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In Lucee Admin there is an unauthenticated RCE vulnerability.

  Note: If access to the Lucee Administrator is blocked the vulnerability is not exploitable.");

  script_tag(name:"affected", value:"Lucee version 5.3.5.96 and prior, 5.3.6.x through 5.3.6.67 and
  5.3.7.x through 5.3.7.46.");

  script_tag(name:"solution", value:"Update to version 5.3.5.96, 5.3.6.68, 5.3.7.47 or later.");

  script_xref(name:"URL", value:"https://github.com/lucee/Lucee/security/advisories/GHSA-2xvv-723c-8p7r");
  script_xref(name:"URL", value:"https://github.com/httpvoid/writeups/blob/main/Apple-RCE.md");

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

if (version_is_less(version: version, test_version: "5.3.5.96")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.5.96", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3.6", test_version2: "5.3.6.67")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.6.68", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3.7", test_version2: "5.3.7.46")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.7.47", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
