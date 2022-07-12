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
  script_oid("1.3.6.1.4.1.25623.1.0.113368");
  script_version("2019-04-25T11:36:15+0000");
  script_tag(name:"last_modification", value:"2019-04-25 11:36:15 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-08 10:45:55 +0000 (Mon, 08 Apr 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HP LaserJet Printers Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"HP LaserJet Printers could allow a remote attacker to bypass security restrictions,
  caused by missing authentication for critical function.
  By sending a specially-crafted request, an attacker could exploit this vulnerability
  to change configuration settings or gain administrative access.");
  script_tag(name:"vuldetect", value:"Tries to access administrative settings.");
  script_tag(name:"affected", value:"Following HP Printers are affected:

  - LaserJet P4014

  - LaserJet P4015

  - LaserJet 5200");
  script_tag(name:"solution", value:"Set an administrator password under the /password.html URL.");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/158953");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

#nb: CP4025 are sometimes detected as "CP4020", but they are still vulnerable
#nb: Same for P3015
#nb: CP Printers are sometimes detected as "laserjet" and sometimes as "color_laserjet"

cpe_list = make_list( 'cpe:/h:hp:laserjet:p4014',
                      'cpe:/h:hp:laserjet:p4015',
                      'cpe:/h:hp:laserjet:5200',
                      'cpe:/h:hp:laserjet:cp4520',
                      'cpe:/h:hp:color_laserjet:cp4520',
                      'cpe:/h:hp:laserjet:cp4025',
                      'cpe:/h:hp:color_laserjet:cp4025',
                      'cpe:/h:hp:laserjet:cp4020',
                      'cpe:/h:hp:color_laserjet:cp4020',
                      'cpe:/h:hp:laserjet:p3015',
                      'cpe:/h:hp:laserjet:p3010' );

if( isnull( result = get_single_app_ports_from_list( cpe_list: cpe_list ) ) ) exit( 0 );

port = result["port"];

if( ! location = get_app_location( cpe: result["cpe"], port: port ) ) exit( 0 );

url = "/password.html";

buf = http_get_cache( port: port, item: url );

if( buf =~ 'Use the fields below to set or change the Administrator Password' ) {
  report = report_vuln_url( port: port, url: url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
