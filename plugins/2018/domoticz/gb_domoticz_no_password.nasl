###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_domoticz_no_password.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# Domoticz No Password
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113252");
  script_version("$Revision: 12026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-23 10:40:44 +0200 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Domoticz No Password");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_domoticz_detect.nasl");
  script_require_ports("Services/www", 8081);
  script_mandatory_keys("domoticz/detected");

  script_tag(name:"summary", value:"By default, the full control dashboard of Domoticz
  does not require a password.");
  script_tag(name:"vuldetect", value:"Tries to access the control dashboard without a password.");
  script_tag(name:"affected", value:"All Domoticz installations.");
  script_tag(name:"solution", value:"Set a password.");

  script_xref(name:"URL", value:"http://www.domoticz.com/");

  exit(0);
}

CPE = "cpe:/a:domoticz:domoticz";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( location == "/" )
  location = "";

target_url = location + "/json.htm?type=command&param=getconfig";

buf = http_get_cache( item: target_url, port: port );
if( buf =~ '200 OK' && buf !~ '403 Forbidden' && buf =~ '"DashboardType"' ) {
  report = report_vuln_url(  port: port, url: target_url );
  report = 'It was possible to access the control dashboard without a password.\r\n' + report;
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
