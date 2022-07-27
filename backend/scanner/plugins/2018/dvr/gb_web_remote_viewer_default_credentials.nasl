###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_web_remote_viewer_default_credentials.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Web Remote Viewer Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.113240");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-01 12:07:22 +0200 (Wed, 01 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Web Remote Viewer Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_web_remote_viewer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("web_remote_viewer/detected");

  script_tag(name:"summary", value:"Web Remote Viewer has
  the default username 'ADMIN' with the default password '1234'.");
  script_tag(name:"vuldetect", value:"Tries to login using the default username and password.");
  script_tag(name:"affected", value:"All IP Cameras running Web Remote Viewer.");
  script_tag(name:"solution", value:"Change the password of the 'ADMIN' account.");

  exit(0);
}

CPE = "cpe:/a:dvr:web_remote_viewer";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

url = location;
if ( location == "/" )
  url = "";
url = url + "/html/live.htm";

username = "ADMIN";
password = "1234";

auth_header = make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) );
req = http_get_req( port: port, url: url, add_headers: auth_header );
buf = http_keepalive_send_recv( port: port, data: req );

if( buf =~ "200 OK" && buf =~ '<div id="lang_[Cc]hannel[Nn]o">[Cc]hannel [Nn]o[.]</div>' ) {
  report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
