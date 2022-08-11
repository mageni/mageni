# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142721");
  script_version("2019-08-09T03:23:09+0000");
  script_tag(name:"last_modification", value:"2019-08-09 03:23:09 +0000 (Fri, 09 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-09 02:52:33 +0000 (Fri, 09 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2019-14748", "CVE-2019-14749", "CVE-2019-14750");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("osTicket < 1.10.7, 1.12.x < 1.12.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("osticket_detect.nasl");
  script_mandatory_keys("osticket/installed");

  script_tag(name:"summary", value:"osTicket is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"osTicket is prone to multiple vulnerabilities:

  - Persistent XSS vulnerability (CVE-2019-14748)

  - CSV injection vulnerability (CVE-2019-14749)

  - Stored XSS vulnerability (CVE-2019-14750)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"osTicket prior to version 1.10.7 and 1.12.");

  script_tag(name:"solution", value:"Update to version 1.10.7, 1.12.1 or later.");

  script_xref(name:"URL", value:"https://github.com/osTicket/osTicket/releases/tag/v1.10.7");
  script_xref(name:"URL", value:"https://github.com/osTicket/osTicket/releases/tag/v1.12.1");

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

if (version_is_less(version: version, test_version: "1.10.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.12.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
