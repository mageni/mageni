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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113447");
  script_version("2019-07-22T11:52:47+0000");
  script_tag(name:"last_modification", value:"2019-07-22 11:52:47 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-22 13:29:14 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10664", "CVE-2019-10678");

  script_name("Domoticz <= 4.10577 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_domoticz_detect.nasl");
  script_mandatory_keys("domoticz/detected");

  script_tag(name:"summary", value:"Domoticz is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - SQL Injection via the idx parameter in CWebServer::GetFloorPlanImage in WebServer.cpp.

  - Unfiltered Input of \n and \r as argument options allows for command execution.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  read sensitive information such as login credentials and execute arbitrary commands on the target machine.");
  script_tag(name:"affected", value:"Domoticz through version 4.10577.");
  script_tag(name:"solution", value:"Update to version 4.10658.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/152678/Domoticz-4.10577-Unauthenticated-Remote-Command-Execution.html");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46773/");

  exit(0);
}

CPE = "cpe:/a:domoticz:domoticz";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.10658" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.10658", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
