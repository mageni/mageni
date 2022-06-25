###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lantronix_device_detect_telnet.nasl 10888 2018-08-10 12:08:02Z cfischer $
#
# Lantronix Devices Detection (Telnet)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108302");
  script_version("$Revision: 10888 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-11-29 08:03:31 +0100 (Wed, 29 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Lantronix Devices Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23, 9999);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"summary", value:"This script performs Telnet based detection of Lantronix Devices.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("host_details.inc");

port   = get_telnet_port( default:9999 ); # Most devices are running on 9999 but there are a few like MSS on 23/tcp
banner = get_telnet_banner( port:port );

# Lantronix MSS-VIA Version V3.6/3(000201)
# Lantronix MSS4 Version B3.7/108(030909)
# Lantronix SCS1600 Version 2.0/5(040701)
# Default bannner, they might appear on e.g. 23/tcp or 9999/tcp

if( egrep( string:banner, pattern:"^Lantronix .* Version ", icase:FALSE ) ||
    # nb: Both are covered in a separate Detection-NVT
    ( ( banner !~ "(IQinVision|IQEye) " ) && banner =~ 'Type HELP at the .* prompt for assistance' ) ||
    ( "Lantronix" >< banner && ( "Password :" >< banner || ( "Press Enter" >< banner && "Setup Mode" >< banner ) ) ) ||
    # Some branded devices not providing the "Lantronix" banner but still using their firmware.
    # nb: Only use / report if this was detected on the (on some devices) hardcoded port 9999/tcp.
    ( port == 9999 && "Software version " >< banner && "MAC address " >< banner ) ) {

  set_kb_item( name:"lantronix_device/detected", value:TRUE );
  set_kb_item( name:"lantronix_device/telnet/detected", value:TRUE );
  set_kb_item( name:"lantronix_device/telnet/port", value:port );

  version = "unknown";

  vers = eregmatch( pattern:"(Software version|Version) [VB]?([0-9.]+)", string:banner );
  if( vers[2] ) {
    version = vers[2];
    set_kb_item( name:"lantronix_device/telnet/" + port + "/concluded", value:vers[0] );
  } else {
    set_kb_item( name:"lantronix_device/telnet/" + port + "/concluded", value:bin2string( ddata:banner, noprint_replacement:'' ) );
  }
  set_kb_item( name:"lantronix_device/telnet/" + port + "/version", value:version );

  type = "unknown";

  if( "Lantronix" >!< banner && "Software version " >< banner && "MAC address " >< banner ) {
    type = "Branded";
  } else if( "Lantronix Inc. - Modbus Bridge" >< banner ) {
    type = "Modbus Bridge";
  } else if( "Lantronix Universal Device Server" >< banner ) {
    type = "UDS";
  } else if( "Lantronix Demo Server" >< banner ) {
    type = "Demo Server";
  } else if( "Lantronix CoBox" >< banner ) {
    type = "CoBox";
  } else if( "Sielox/Lantronix Network Adaptor" >< banner || "Checkpoint/Lantronix Network Adaptor" >< banner ) {
    type = "Branded";
  } else if( _type = eregmatch( pattern:"Lantronix ([A-Z0-9-]+) ", string:banner ) ) {
    type = _type[1];
  }

  if ( type == "unknown" ) {
    username = "login";
    access = FALSE;

    soc = open_sock_tcp( port );
    if( soc ) {

      recv1 = recv( socket:soc, length:2048, timeout:10 );

      if ( "prompt for assistance" >< recv1 && "Username>" >< recv1 ) {
        send( socket:soc, data:username + '\r\n' );
        recv2 = recv( socket:soc, length:2048, timeout:10 );

        if ( recv2 =~ "Local_.+>" ) {
          access = TRUE;
          set_kb_item(name:"lantronix_device/telnet/" + port + "/access", value:TRUE );
        }
      }

      if ( access ) {
        send( socket:soc, data:'show server\r\n' );
        recv3 = recv( socket:soc, length:2048, timeout:10 );
        # Ident String: EPS100
        typerecv = eregmatch( pattern: "Ident String: ([a-zA-Z0-9]+)", string:bin2string( ddata:recv3, noprint_replacement:'' ) );
        if(!isnull(typerecv[1])){
          type = typerecv[1];
        }
      }
      close( soc );
    }
    # nb: We don't want to report other devices which might have the same "Type HELP"
    # banner as Lantronix devices.
    exit( 0 );
  }

  set_kb_item( name:"lantronix_device/telnet/" + port + "/type", value:type );

  if( mac = eregmatch( pattern:"MAC address ([0-9a-fA-F]{12})", string:bin2string( ddata:banner, noprint_replacement:'' ) ) ) {
    plain_mac = mac[1];
    for( i = 0; i < 12; i++ ) {
      full_mac += plain_mac[i];
      if( i % 2 && i != 11 ) full_mac += ":";
    }
    register_host_detail( name:"MAC", value:full_mac, desc:"Get the MAC Address via Lantronix Telnet banner" );
    replace_kb_item( name:"Host/mac_address", value:full_mac );
  }
}
exit( 0 );
