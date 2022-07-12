# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144107");
  script_version("2020-06-15T07:19:52+0000");
  script_tag(name:"last_modification", value:"2020-06-15 12:06:35 +0000 (Mon, 15 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-15 07:00:06 +0000 (Mon, 15 Jun 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2020-1408", "CVE-2020-13977");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios Core < 4.4.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");

  script_tag(name:"summary", value:"Nagios Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nagios Core is prone to multiple vulnerabilities:

  - Authenticated vulnerabilities in histogram.js, map.js, trends.js (CVE-2020-1408)

  - URL injection vulnerability (CVE-2020-13977)");

  script_tag(name:"affected", value:"Nagios Core version 4.4.5 and prior.");

  script_tag(name:"solution", value:"Update to Nagios Core version 4.4.6 or later.");

  script_xref(name:"URL", value:"https://anhtai.me/nagios-core-4-4-5-url-injection/");
  script_xref(name:"URL", value:"https://www.nagios.org/projects/nagios-core/history/4x/");

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

if (version_is_less(version: version, test_version: "4.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
