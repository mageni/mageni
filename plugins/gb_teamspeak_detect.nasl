###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamspeak_detect.nasl 9611 2018-04-25 14:25:08Z cfischer $
#
# TeamSpeak 2/3 Server Detection (TCP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100681");
  script_version("$Revision: 9611 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 16:25:08 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-06-18 12:11:06 +0200 (Fri, 18 Jun 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("TeamSpeak 2/3 Server Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/teamspeak-serverquery", 10011, "Services/teamspeak-tcpquery", 51234, 30033);

  script_tag(name:"summary", value:"This host is running a TeamSpeak 2/3 Server. TeamSpeak is proprietary Voice over IP
  software that allows users to speak on a chat channel with other users, much like a telephone conference call.");

  script_xref(name:"URL", value:"http://www.teamspeak.com/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

sport = get_kb_list( "Services/teamspeak-serverquery" );
if( ! sport ) sport = make_list( 10011 );

tport = get_kb_list( "Services/teamspeak-tcpquery" );
if( ! tport ) tport = make_list( 51234 );

foreach port( make_list( sport, tport ) ) {

  if( ! get_port_state( port ) ) continue;
  soc = open_sock_tcp( port );
  if( ! soc ) continue;

  buf = recv( socket:soc, length:16 );
  if( isnull( buf ) && "[TS]" >!< buf && "TS3" >!< buf ) {
    close( soc );
    continue;
  }

  send( socket:soc, data:'version\n' );
  buf = recv( socket:soc, length:256 );
  vers = "unknown";
  install = port + '/tcp';

  if( "version" >< buf && "msg" >< buf ) {

    version = eregmatch( pattern:"version=([^ ]+) (build=([^ ]+))*", string:buf );

    if( ! isnull( version[1] ) ) vers = version[1];
    if( ! isnull( version[3] ) ) vers += ' build=' + version[3];

    register_service( port:port, proto:"teamspeak-serverquery" );
    app = "TeamSpeak 3 Server";
    set_kb_item( name:"teamspeak3_server/" + port, value:vers );
    set_kb_item( name:"teamspeak3_server/installed", value:TRUE );
    cpe = "cpe:/a:teamspeak:teamspeak3";

  } else {

    send( socket:soc, data:'ver\n' );
    buf = recv( socket:soc, length:256 );

    version = eregmatch( pattern:"([0-9.]+)", string:buf );
    if( ! isnull( version[1] ) ) vers = version[1];

    register_service( port:port, proto:"teamspeak-tcpquery" );
    app = "TeamSpeak 2 Server";
    set_kb_item( name:"teamspeak2_server/" + port, value:vers );
    set_kb_item( name:"teamspeak2_server/installed", value:TRUE );
    cpe = "cpe:/a:teamspeak:teamspeak2";
  }

  close( soc );

  cpe2 = build_cpe( value:version[1], exp:"^([0-9.]+)(-[0-9a-zA-Z]+)?", base:cpe + ":" );
  cpe2 = str_replace( string:cpe2, find:"-", replace:"" );
  if( isnull( cpe2 ) ) {
    cpe2 = cpe + ":::server";
  } else {
    cpe2 = cpe2 + "::server";
  }

  register_product( cpe:cpe2, location:install, port:port );

  log_message( data:build_detection_report( app:app,
                                            version:version[1],
                                            install:install,
                                            cpe:cpe2,
                                            concluded:version[0] ),
                                            port:port );
}

# This is the file transfer port of TS3.
# There is currently no way to identify this service
# as it won't reply even on a successful upload.
# For now just register the default 30033 (if open)
if( "teamspeak3_server/installed" ) {

  port = 30033;
  if( ! get_port_state( port ) ) exit( 0 );
  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  register_service( port:port, proto:"teamspeak-filetransfer", message:"A TS3 file transfer service seems to be running on this port" );
  log_message( port:port, data:"A TS3 file transfer service seems to be running on this port" );
  close( soc );
}

exit( 0 );
