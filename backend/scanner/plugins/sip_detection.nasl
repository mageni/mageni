##############################################################################
# OpenVAS Vulnerability Test
# $Id: sip_detection.nasl 13732 2019-02-18 10:39:53Z cfischer $
#
# Detect SIP Compatible Hosts (UDP)
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11963");
  script_version("$Revision: 13732 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 11:39:53 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detect SIP Compatible Hosts (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Service detection");
  script_dependencies("gb_open_udp_ports.nasl", "sip_detection_tcp.nasl");
  script_require_udp_ports("Services/udp/unknown", 5060, 5061, 5070);

  script_xref(name:"URL", value:"http://www.cs.columbia.edu/sip/");

  script_tag(name:"summary", value:"A Voice Over IP service is listening on the remote port.

  The remote host is running SIP (Session Initiation Protocol), a protocol
  used for Internet conferencing and telephony.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("sip.inc");

proto = "udp";

port = get_unknown_port( default:5060, ipproto:proto );
banner = sip_get_banner( port:port, proto:proto );

# nb: sip_get_banner is setting this banner if it has detected a SIP service.
if( ! full_banner = get_kb_item( "sip/full_banner/" + proto + "/" + port ) )
  exit( 0 );

if( banner ) {

  set_kb_item( name:"sip/banner/available", value:TRUE );
  serverbanner = get_kb_item( "sip/server_banner/" + proto + "/" + port );
  if( serverbanner )
    desc = "Server Banner: " + serverbanner;

  uabanner = get_kb_item( "sip/useragent_banner/" + proto + "/" + port );
  if( uabanner ) {
    if( desc )
      desc += '\n';
    desc += "User-Agent: " + uabanner;
  }
}

options = get_kb_item( "sip/options_banner/" + proto + "/" + port );
if( options )
  desc += '\nSupported Options: ' + options;

desc += '\n\nFull banner output:\n\n' + full_banner;

set_kb_item( name:"sip/detected", value:TRUE );
set_kb_item( name:"sip/port_and_proto", value:port + "#-#" + proto );

log_message( port:port, protocol:proto, data:desc );
register_service( port:port, ipproto:proto, proto:"sip", message:"A service supporting the SIP protocol was idendified." );

exit( 0 );