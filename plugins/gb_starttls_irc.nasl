###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_irc.nasl 11915 2018-10-16 08:05:09Z cfischer $
#
# SSL/TLS: IRC 'STARTTLS' Command Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108072");
  script_version("$Revision: 11915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 10:05:09 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-07 11:18:02 +0100 (Tue, 07 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: IRC 'STARTTLS' Command Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/irc", 6667);

  script_add_preference(name:"Run routine", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"Checks if the remote IRC server supports SSL/TLS with the 'STARTTLS' command.

  Note: This script is not running by default as most IRC servers are throttling too many
  connections and rejecting further requests. If you want to test your IRC server please
  exclude the IP of the scanner from this throttling mechanism.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://ircv3.net/specs/extensions/tls-3.1.html");

  exit(0);
}

run_script = script_get_preference( "Run routine" );
if( "no" >< run_script ) exit( 0 );

port = get_kb_item( "Services/irc" );
if( ! port ) port = 6667;
if( ! get_port_state( port ) ) exit( 0 );

if( get_port_transport( port ) > ENCAPS_IP ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:'STARTTLS\r\n' );

while( buf = recv_line( socket:soc, length:2048 ) ) {
  if( ":STARTTLS successful" >< buf ) {
    set_kb_item( name:"irc/" + port + "/starttls", value:TRUE );
    set_kb_item( name:"starttls_typ/" + port, value:"irc" );
    log_message( port:port, data:"The remote IRC server supports SSL/TLS with the 'STARTTLS' command." );
    close( soc );
    exit( 0 );
  }
}

close( soc );
exit( 0 );