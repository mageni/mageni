###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamspeak_udp_detect.nasl 8236 2017-12-22 10:28:23Z cfischer $
#
# TeamSpeak 3 Server Detection (UDP)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108070");
  script_version("$Revision: 8236 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 11:28:23 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-02-05 13:05:06 +0100 (Sun, 05 Feb 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("TeamSpeak 3 Server Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 9987, 9988, 9989);

  script_tag(name:"summary", value:"This host is running a TeamSpeak 3 Server. TeamSpeak is proprietary Voice over IP
  software that allows users to speak on a chat channel with other users, much like a telephone conference call.");

  script_xref(name:"URL", value:"http://www.teamspeak.com/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

proto = "udp";
port = get_unknown_port( default:9987, ipproto:proto );

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

# The TS3INIT packet
req = raw_string( 0x54, 0x53, 0x33, 0x49, 0x4e, 0x49, 0x54, 0x31, 0x00, 0x65, 0x00, 0x00, 0x88, 0x07, 0x95, 0x4b,
                  0x40, 0x00, 0x58, 0x97, 0x09, 0x2d, 0xf7, 0xbb, 0xb2, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00 );

send( socket:soc, data:req );
res = recv( socket:soc, length:32 );
close( soc );
if( ! res || strlen( res != 32 ) ) exit( 0 );

if( "TS3INIT" >< res ) {

  version = "unknown";
  cpe = "cpe:/a:teamspeak:teamspeak3";
  install = port + "/" + proto;

  register_service( port:port, proto:"ts3", ipproto:proto );

  register_product( cpe:cpe, location:install, port:port, proto:proto );
  log_message( data:build_detection_report( app:"TeamSpeak 3 Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe ),
                                            port:port,
                                            proto:proto );
}

exit( 0 );
