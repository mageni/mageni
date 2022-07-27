###############################################################################
# OpenVAS Vulnerability Test
# $Id: lcdproc_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# LCDproc server detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10379");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("LCDproc server detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 13666);

  script_tag(name:"solution", value:"Disable access to this service from outside by disabling
  access to TCP port 13666 (default port used).");

  script_tag(name:"summary", value:"LCDproc is a system that is used to display system information and other data
  on an LCD display (or any supported display device, including curses
  or text).");

  script_tag(name:"impact", value:"The LCDproc version 0.4 and above uses a client-server protocol, allowing
  anyone with access to the LCDproc server to modify the displayed content.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port( default:13666 );

soc = open_sock_tcp( port );

if( soc ) {
  req = string( "hello" );

  send(socket:soc, data:req);
  result = recv(socket:soc, length:4096);

  if( "connect LCDproc" >< result ) {
    resultrecv = strstr( result, "connect LCDproc " );
    resultsub = strstr( resultrecv, string( "lcd " ) );
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "connect LCDproc ";
    resultrecv = resultrecv - "lcd ";

    banner = "LCDproc (";
    banner = banner + resultrecv;
    banner = banner + ') was found running on the target.\n';

    set_kb_item( name:"lcdproc/detected", value:TRUE );
    register_service( port:port, proto:"lcdproc" );
    log_message( port:port, data:banner );
    exit( 0 );
  }
}

exit( 0 );