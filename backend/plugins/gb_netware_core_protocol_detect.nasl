###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netware_core_protocol_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# NetWare Core Protocol (NCP) Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108316");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-01-12 08:57:15 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetWare Core Protocol (NCP) Detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 524);

  script_tag(name:"summary", value:"The script checks the presence of a service supporting the
  NetWare Core Protocol (NCP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("dump.inc");

port = get_unknown_port( default:524 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# From pre2008/NDS_Object_Enum.nasl
req = raw_string( 0x44, 0x6d, 0x64, 0x54,  # NCP over IP signature: Demand Transport
                  0x00, 0x00, 0x00, 0x17,  # NCP over IP Length: 0x00000017 (23 bytes)
                  0x00, 0x00, 0x00, 0x01,  # NCP over IP version: 1
                  0x00, 0x00, 0x00, 0x00,  # NCP over IP Reply Buffer Size: 0
                  0x11, 0x11,              # Type: Create a service connection
                  0x00,                    # Initial sequence number 0x00
                  0xff,                    # Connection Number low, 0xff (255) wildcard
                  0x01,                    # Task Number: 1
                  0xff,                    # Connection Number high, 0xff (255) wildcard
                  0x04 );                  # Group: Connection

send( socket:soc, data:req );
res = recv( socket:soc, length:64 );
close( soc );

if( res && hexstr( res ) =~ "^744E635000000010333300" ) {
  set_kb_item( name:"netware/ncp/" + port + "/detected", value:TRUE );
  set_kb_item( name:"netware/ncp/detected", value:TRUE );

  register_service( port:port, proto:"ncp", message:"A service supporting the NetWare Core Protocol is running at this port." );
  log_message( port:port, data:"A service supporting the NetWare Core Protocol is running at this port." );
}

exit( 0 );