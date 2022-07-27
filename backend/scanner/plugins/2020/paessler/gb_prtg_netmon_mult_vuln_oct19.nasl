# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:paessler:prtg_network_monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112711");
  script_version("2020-03-18T11:21:40+0000");
  script_tag(name:"last_modification", value:"2020-03-18 13:55:00 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-18 11:14:00 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2019-11074");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PRTG Network Monitor < 19.3.52.3502 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prtg_network_monitor_detect.nasl");
  script_mandatory_keys("prtg_network_monitor/installed");

  script_tag(name:"summary", value:"PRTG Network Monitor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PRTG Network Monitor is prone to multiple vulnerabilities:

  - A potential Denial of Service (DoS) vulnerability of the HTTP Full Web Page sensor (CVE-2019-11074)

  - Reflected XSS vulnerabilities with medium severity on the PRTG core server. The potential vulnerabilities
  affected tag filters, object IDs, and the contact support/feedback page.");

  script_tag(name:"affected", value:"PRTG Network Monitor prior to version 19.3.52.3502.");

  script_tag(name:"solution", value:"Update to version 19.3.52.3502 or later.");

  script_xref(name:"URL", value:"https://www.paessler.com/prtg/history/stable");
  script_xref(name:"URL", value:"https://how2itsec.blogspot.com/2019/10/security-fixes-in-prtg-1935152.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "19.3.52.3502")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.3.52.3502", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
