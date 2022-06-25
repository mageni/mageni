# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = 'cpe:/a:paessler:prtg_network_monitor';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142304");
  script_version("2019-04-25T07:55:31+0000");
  script_tag(name:"last_modification", value:"2019-04-25 07:55:31 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-25 07:46:33 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2018-19204", "CVE-2018-14683");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PRTG Network Monitor < 19.1.49.1966 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prtg_network_monitor_detect.nasl");
  script_mandatory_keys("prtg_network_monitor/installed");

  script_tag(name:"summary", value:"PRTG Network Monitor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PRTG Network Monitor is prone to multiple vulnerabilities:

  - DoS vector in the PRTG API

  - Potential attack vector for malicious activities like remote code execution (CVE-2018-19204)

  - XSS vulnerabilities in the PRTG web interface (CVE-2018-14683)");

  script_tag(name:"affected", value:"PRTG Network Monitor prior to version 19.1.49.1966.");

  script_tag(name:"solution", value:"Update to version 19.1.49.1966 or later.");

  script_xref(name:"URL", value:"https://www.paessler.com/prtg/history/stable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "19.1.49.1966")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.1.49.1966", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
