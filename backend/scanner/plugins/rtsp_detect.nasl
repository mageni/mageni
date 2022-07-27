###############################################################################
# OpenVAS Vulnerability Test
# $Id: rtsp_detect.nasl 13725 2019-02-18 09:06:02Z cfischer $
#
# RTSP Server type and version
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.10762");
  script_version("$Revision: 13725 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 10:06:02 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RTSP Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
  script_family("Service detection");
  script_dependencies("find_service5.nasl");
  script_require_ports("Services/rtsp", 554);

  script_tag(name:"summary", value:"This detects the RTSP Server's type and version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("sip.inc");

not_in_kb = FALSE;
port = get_kb_item( "Services/rtsp" );
if( ! port ) {
  port = 554;
  not_in_kb = TRUE;
}

if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

data = string( "OPTIONS * RTSP/1.0\r\n\r\n" );
send( socket:soc, data:data );
header = recv( socket:soc, length:1024 );
close( soc );

if( header =~ "^RTSP/1\.[0-9]+ " && ( "CSeq: " >< header || "Public: " >< header || "Server: " >< header ) ) {
  found = TRUE;
} else {

  # nb: Some RTSP services seems to no answer to the OPTIONS probe above and in find_service2.nasl
  # but answering to the SIP OPTIONS request (see find_service5.nasl as well).
  soc = open_sock_tcp( port );
  if( soc ) {
    data = sip_construct_options_req( port:port, proto:"tcp" );
    send( socket:soc, data:data );
    header = recv( socket:soc, length:1024 );
    close( soc );
    if( header =~ "^RTSP/1\.[0-9]+ " && ( "CSeq: " >< header || "Public: " >< header || "Server: " >< header ) ) {
      found = TRUE;
    }
  }
}

if( found ) {

  if( ! not_in_kb )
    register_service( proto:"rtsp", port:port );

  server = egrep( pattern:"Server:", string:header, icase:TRUE );

  if( server ) {
    server = chomp( server );
    set_kb_item( name:"RTSP/banner/available", value:TRUE );
    set_kb_item( name:"RTSP/" + port + "/Server", value:server );
    report = string( "The remote RTSP server is :\n\n", server, "\n\n" );
  }

  report += string( "All RTSP Header for 'OPTIONS *' method:\n\n", chomp( header ) );
  log_message( port:port, data:report );
}

exit( 0 );