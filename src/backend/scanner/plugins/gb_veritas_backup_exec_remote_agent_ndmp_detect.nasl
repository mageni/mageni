# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103705");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-04-26 12:18:48 +0200 (Fri, 26 Apr 2013)");

  script_name("Veritas Backup Exec Remote Agent Detection (NDMP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports(10000);

  script_tag(name:"summary", value:"Network Data Management Protocol (NDMP) based detection of the
  Veritas Backup Exec Agent.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("dump.inc");

port = 10000;
if( ! get_port_state( port ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

# nb: Wait for the NOTIFY_CONNECTED
buf = recv( socket:soc, length:4 );
if( isnull( buf ) ) {
  close( soc );
  exit( 0 );
}

len = getword( blob:buf, pos:2 );
buf = recv( socket:soc, length:len );
if( isnull( buf ) ) {
  close( soc );
  exit( 0 );
}

if( strlen( buf ) < 16 || ord( buf[15] ) != 2 || ord( buf[14] ) != 5 ) {
  close( soc );
  exit( 0 );
}

#nb: this is a NDMP_CONFIG_GET_SERVER_INFO request, but without sequence number or timestamp
req = raw_string( 0x80, 0x00, 0x00, 0x18 ) + # Fragment header (Last fragment = yes, Fragment length: 24
      raw_string( 0x00, 0x00, 0x00, 0x00 ) + # Sequence - 0 in this case
      raw_string( 0x00, 0x00, 0x00, 0x00 ) + # Time
      raw_string( 0x00, 0x00, 0x00, 0x00 ) + # Request (0)
      raw_string( 0x00, 0x00, 0x01, 0x08 ) + # Message (CONFIG_GET_HOST_INFO)
      raw_string( 0x00, 0x00, 0x00, 0x00 ) + # Reply Sequence
      raw_string( 0x00, 0x00, 0x00, 0x00 );  # Error (NO_ERR)

send( socket:soc, data:req );
buf = recv( socket:soc, length:4 );

if( strlen( buf ) < 4 ) {
  close( soc );
  exit( 0 );
}

len = getword( blob:buf, pos:2 );
buf = recv( socket:soc, length:len );
# VERITAS Software, Corp.     Remote Agent for NT     9.1
if( ! buf || "VERITAS" >!< buf ) {
  close( soc );
  exit( 0 );
}

concluded = bin2string( ddata:buf, noprint_replacement:" " );

#nb: the NDMP request seems to be a Veritas proprietary NDMP request to retrieve the version.
# sadly, for newer version this usually returns NOT_AUTHORIZED_ERROR
req = raw_string( 0x80, 0x00, 0x00, 0x24 ) +                                                # Fragment header (Last fragment = yes, Fragment length: 24 header + 12 body
      raw_string( 0x00, 0x00, 0x00, 0x00 ) +                                                # Sequence - 0 in this case
      raw_string( 0x00, 0x00, 0x00, 0x00 ) +                                                # Time
      raw_string( 0x00, 0x00, 0x00, 0x00 ) +                                                # Request (0)
      raw_string( 0x00, 0x00, 0xf3, 0x1b ) +                                                # Message Veritas-specific type for getting version
      raw_string( 0x00, 0x00, 0x00, 0x00 ) +                                                # Reply Sequence
      raw_string( 0x00, 0x00, 0x00, 0x00 ) +                                                # Error (NO_ERR)
      raw_string( 0x00, 0x00, 0x00, 0x06, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x00, 0x00 ); # Message body

send( socket:soc, data:req );
buf = recv( socket:soc, length:4 );

if( strlen( buf ) < 4 ) {
  close( soc );
  exit( 0 );
}

len = getword( blob:buf, pos:2 );
buf = recv( socket:soc, length:len );
#nb: If length is smaller, most likely a NOT_AUTHORIZED_ERROR was received
# successful:           0000000362fb3b2d000000010000f31b0000000000000000000000000000000100000004000000000000000e00000001000006fa0000045f00000000
# NOT_AUTHORIZED_ERROR: 0000000362fb3b67000000010000f31b0000000000000004

close( soc );

version = "unknown";

if( strlen( buf ) >= 56 ) {
  pos = 40;

  for( i = 0; i < 4; i++ ) {
    vers += getdword( blob:buf, pos:pos );
    if( i < 3 )
      vers += ".";
    pos = pos + 4;
  }
  version = vers;
}

set_kb_item( name:"veritas/backup_exec_remote_agent/detected", value:TRUE );
set_kb_item( name:"veritas/backup_exec_remote_agent/ndmp/detected", value:TRUE );
set_kb_item( name:"veritas/backup_exec_remote_agent/ndmp/" + port + "/installs",
             value:port + "#---#Veritas Backup Exec Remote Agent#---#/#---#" +
                   version + "#---#" + concluded );

service_register( port:port, proto:"ndmp", message:"A Veritas Backup Exec Remote Agent seems to be running on this port." );

exit( 0 );
