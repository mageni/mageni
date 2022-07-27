###############################################################################
# OpenVAS Vulnerability Test
#
# Gnutella servent detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10946");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Gnutella servent detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("find_service.nasl");
  # Gnutella servent _might_ be detected as a web server
  script_require_ports("Services/www", "Services/unknown", 6346);

  script_tag(name:"summary", value:"We detected a Gnutella 'servent'.
  This file sharing software works in peer to peer mode.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");

ports = get_unknown_port_list( default:6346 ); # Detection is commeted out in nasl_builtin_find_service.c

foreach port ( ports ) {

  soc = open_sock_tcp( port );
  if( soc ) {

    send( socket:soc, data:'GNUTELLA CONNECT/0.4\r\n\r\n' );
    answer = recv( socket:soc, length:500 );
    close( soc );

    if( "GNUTELLA OK" >< answer ) {
      log_message( port:port );
      register_service( port:port, proto:"gnutella" );
    }
  }
}

# Gnutella servent _might_ be detected as a web server
port = get_http_port( default:6346 );

banner = get_http_banner( port:port );
if( ! banner ) {
  soc = open_sock_tcp( port );
  if( soc ) {
    send( socket:soc, data:'GET / HTTP/1.0\r\n\r\n' );
    banner = http_recv( socket:soc );
    close( soc );
  } else {
    exit( 0 );
  }
}

# We should probably add more regex here. But there are 100+ Gnutella software
if( egrep( pattern:"Gnutella|BearShare", string:banner, icase:TRUE ) ) {
  report = "Although this service did not answer to Gnutella protocol 0.4, it might be a Gnutella server.";
  log_message( port:port, data:report );
}

exit( 0 );