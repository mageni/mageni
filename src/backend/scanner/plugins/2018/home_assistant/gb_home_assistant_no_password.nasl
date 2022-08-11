###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_home_assistant_no_password.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Home Assistant Dashboard No Password
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
  script_oid("1.3.6.1.4.1.25623.1.0.113250");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-22 12:10:24 +0200 (Wed, 22 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Home Assistant Dashboard No Password");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_home_assistant_detect.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("home_assistant/detected");

  script_tag(name:"summary", value:"By default, the full control dashboard of Home Assistant
  does not require a password.");
  script_tag(name:"vuldetect", value:"Tries to access control dashboard without a password.");
  script_tag(name:"affected", value:"All versions of Home Assistant.");
  script_tag(name:"solution", value:"Set a password.");

  script_xref(name:"URL", value:"https://www.home-assistant.io/");

  exit(0);
}

CPE = "cpe:/a:home_assistant:home_assistant";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( location == "/" )
  location = "";

path = location + "/states";
buf = http_get_cache( port: port, item: path );
buf = ereg_replace( pattern: '[\r\n]*', string:buf, replace:'', icase: TRUE );
if( buf =~ '200 OK' && buf =~ 'window.noAuth[ ]*=[ ]*["\']?(true|1)["\']?' ) {
  report = "It was possible to access the control dashboard without a password.";
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
