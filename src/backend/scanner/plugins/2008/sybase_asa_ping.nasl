###############################################################################
# OpenVAS Vulnerability Test
# $Id: sybase_asa_ping.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# Sybase ASA Ping
#
# Authors:
# David Lodge 13/08/2007
# This script is based on sybase_blank_password.nasl which is (C) Tenable Security
#
# Copyright:
# Copyright (C) 2007 David Lodge
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
  script_oid("1.3.6.1.4.1.25623.1.0.80089");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Sybase ASA Ping");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2007 David Lodge");
  script_family("Databases");
  script_require_udp_ports(2638);

  script_xref(name:"URL", value:"http://www.sybase.com/products/databasemanagement/sqlanywhere");

  script_tag(name:"solution", value:"Switch off broadcast listening via the '-sb' switch when starting
  Sybase.");

  script_tag(name:"summary", value:"The remote Sybase SQL Anywhere / Adaptive Server Anywhere database is
  configured to listen for client connection broadcasts, which allows an attacker to see the name and port
  that the Sybase SQL Anywhere / Adaptive Server Anywhere server is running on.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");

port = 2638;
if( ! get_udp_port_state( port ) ) exit( 0 );

req = raw_string(
   0x1b, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x12,
   "CONNECTIONLESS_TDS",
   0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
   0x04, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x03, 0x01, 0x01,
   0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);

soc = open_sock_udp( port );
if( soc ) {

  send( socket:soc, data:req );
  r = recv( socket:soc, length:4096 );
  close( soc );
  if( ! r ) exit( 0 );

  name="";
  length = ord( r[0x27] );
  for( i = 0x28; i < 0x27 + length ; i++ ) {
    name += r[i];
  }

  offset = 0x27 + length + 3;
  serverport = ord( r[offset] ) * 256 + ord( r[offset+1] );

  report = "Database name: " + name + '\n' + "Database port: " + serverport;

  security_message( port:port, protocol:"udp", data:report );
  exit( 0 );
}

exit( 99 );