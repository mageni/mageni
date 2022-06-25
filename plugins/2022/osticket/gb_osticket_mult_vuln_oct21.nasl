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

CPE = "cpe:/a:osticket:osticket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148062");
  script_version("2022-05-05T10:14:17+0000");
  script_tag(name:"last_modification", value:"2022-05-06 10:15:46 +0000 (Fri, 06 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-05 07:13:36 +0000 (Thu, 05 May 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-42235");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("osTicket < 1.14.8, 1.15.x < 1.15.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("osticket_http_detect.nasl");
  script_mandatory_keys("osticket/http/detected");

  script_tag(name:"summary", value:"osTicket is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-42235: SQL injection (SQLi)

  - SSRF External Images

  - Stored XSS / domain whitelist bypass

  - Recipient injection via user's name

  - XSS in advanced search

  - XSS in tasks");

  script_tag(name:"affected", value:"osTicket version 1.14.7 and prior and version 1.15.x through
  1.15.3.");

  script_tag(name:"solution", value:"Update to version 1.14.8, 1.15.4 or later.");

  script_xref(name:"URL", value:"https://github.com/osTicket/osTicket/commit/e28291022e662ffa754e170c09cade7bdadf3fd9");

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

if (version_is_less(version: version, test_version: "1.14.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.15.0", test_version_up: "1.15.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.15.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
