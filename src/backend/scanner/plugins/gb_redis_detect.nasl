###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_redis_detect.nasl 10074 2018-06-05 08:01:45Z cfischer $
#
# Redis Server Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103844");
  script_version("$Revision: 10074 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-06-05 10:01:45 +0200 (Tue, 05 Jun 2018) $");
  script_tag(name:"creation_date", value:"2013-12-02 13:58:18 +0100 (Mon, 02 Dec 2013)");
  script_name("Redis Server Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/redis", 6379);

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("cpe.inc");

cpe = "cpe:/a:redis:redis";
app = "Redis Server";

port = get_kb_item( "Services/redis" );
if( ! port ) port = 6379;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

install = port + "/tcp";

send( socket:soc, data:'PING\r\n' );
recv = recv( socket:soc, length:32 );

if( recv =~ "^\-NOAUTH" ) {
  send( socket:soc, data:'AUTH foobared\r\n' );
  recv = recv( socket:soc, length:32 );
  if( "-ERR invalid password" >< recv ) {
    close( soc );
    set_kb_item( name:"redis/installed", value:TRUE );
    register_service( port:port, proto:"redis" );
    register_and_report_cpe( app:app, concluded:recv, cpename:cpe, insloc:install, regPort:port, extra:"The Redis server is protected by a password." );
    exit( 0 );
  }
  set_kb_item( name:"redis/" + port + "/default_password", value:TRUE );
  set_kb_item( name:"redis/default_password", value:TRUE );
  extra = "Redis Server is protected with the default password 'foobared'.";
} else if( "-DENIED Redis is running in prot" >< recv ) { # nb: The 32 byte length from above...
  close( soc );
  set_kb_item( name:"redis/installed", value:TRUE );
  register_service( port:port, proto:"redis" );
  register_and_report_cpe( app:app, concluded:recv, cpename:cpe, insloc:install, regPort:port, extra:"The Redis server is running in protected mode." );
  set_kb_item( name:"redis/" + port + "/protected_mode", value:TRUE );
  set_kb_item( name:"redis/protected_mode", value:TRUE );
  exit( 0 );
} else if( recv =~ "^\+?PONG" || "-MISCONF Redis is configured to " >< recv ) { # nb: The 32 byte length from above...

  # If the MISCONF is showing up we still can gather the info that the server is unprotected
  # but we need to receive more data before the AUTH below...
  if( "-MISCONF Redis is configured to" >< recv )
    recv_line( socket:soc, length:2048 );

  send( socket:soc, data:'AUTH openvas\r\n' );
  recv = recv( socket:soc, length:64 );
  if( "-ERR Client sent AUTH, but no password is set" >< recv ) {
    set_kb_item( name:"redis/" + port + "/no_password", value:TRUE );
    set_kb_item( name:"redis/no_password", value:TRUE );
    extra = "Redis Server is not protected with a password.";
  }
}

send( socket:soc, data:'info\r\n' );
recv = recv( socket:soc, length:1024 );
close( soc );

if( "redis_version" >!< recv ) exit( 0 );

set_kb_item( name:"redis/installed", value:TRUE );

rv = "unknown";

redis_version = eregmatch( pattern:'redis_version:([^\r\n]+)', string:recv );
if( ! isnull( redis_version[1] ) ) {
  set_kb_item( name:"redis/" + port + "/version", value:redis_version[1] );
  rv = redis_version[1];
  cpe += ":" + rv;
}

register_service( port:port, proto:"redis" );
register_and_report_cpe( app:app, ver:rv, concluded:redis_version[0], cpename:cpe, insloc:install, regPort:port, extra:extra );

exit( 0 );
