###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvpn_udp_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# OpenVPN Detection (UDP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108028");
  script_version("$Revision: 10911 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-05-28 12:39:47 +0100 (Wed, 28 May 2014)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenVPN Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_open_udp_ports.nasl", "gb_openvpn_detect.nasl");
  script_require_udp_ports("Services/udp/unknown", 1194);

  script_tag(name:"summary", value:"The script sends a connection request and attempts to detect an
  OpenVPN server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("misc_func.inc");
include("host_details.inc");

function vpn_req() {
  return raw_string( ( 0x07 << 3 ) | 0x00 ) + mkdword( rand() ) + mkdword( rand() ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00 );
}

port = get_unknown_port( default:1194, ipproto:"udp" );

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

req = vpn_req();
send( socket:soc, data:req );
buf = recv( socket:soc, length:1024, timeout:10 );
close( soc );

if( strlen( buf ) < 14 ) exit( 0 );

if( substr( buf, 9, 13 ) != raw_string( 0x01, 0x00, 0x00, 0x00, 0x00 ) ||
    ( ord( buf[0] ) >> 3 != 0x08 && ord( buf[0] ) >> 3 != 0x05 ) ||
    ord( buf[0] ) & 0x07 != 0x00 ) {
  exit( 0 );
} else {

  register_service( port:port, ipproto:"udp", proto:"openvpn" );

  cpe = "cpe:/a:openvpn:openvpn";
  install = port + "/udp";

  register_product( cpe:cpe, location:install, port:port, proto:"udp" );
  log_message( data:build_detection_report( app:"OpenVPN",
                                            install:install,
                                            cpe:cpe ),
                                            port:port,
                                            proto:"udp" );
}

exit( 0 );