###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendnet_camera_default_credentials.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Trendnet Internet Camera Default Credentials
#
# Authors:
# Adrian Steins <adrian.steinsgreenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112338");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-07-25 14:03:42 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Trendnet Internet Camera Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_trendnet_camera_detect.nasl");
  script_mandatory_keys("trendnet/ip_camera/detected");

  script_tag(name:"summary", value:"Trendnet IP cameras use the default credentials admin:admin.");
  script_tag(name:"vuldetect", value:"Tries to login using default credentials.");
  script_tag(name:"affected", value:"All Trendnet IP cameras.");
  script_tag(name:"solution", value:"Change the default password for the admin account.");

  script_xref(name:"URL", value:"https://www.trendnet.com/");

  exit(0);
}

CPE = "cpe:/h:trendnet:ip_camera";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );

username = "admin";
password = "admin";

auth_header = make_array( 'Authorization', 'Basic ' + base64( str: username + ":" + password ) );
req = http_get_req( port: port, url: "/admin/setup.cgi?page=deviceinfo", add_headers: auth_header );
buf = http_keepalive_send_recv( port: port, data: req );

if( '<title>Pan/Tilt Network Camera</title>' >< buf ||
  'setContent("syslogtag",item_name[_SYS_LOG]);' >< buf ) {

  if ( model_match = eregmatch( pattern: '<img src="images/description_([A-Z0-9-]+).gif">', string: buf, icase: TRUE ) ) {
    model = model_match[1];
    set_kb_item( name: "trendnet/ip_camera/model", value: model );
  }

  report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
  if( model ) report += '\r\n\r\nThe device could be identified as a Trendnet ' + model + '.';

  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
