###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lantronix_mgm_tcp_detect.nasl 8020 2017-12-07 08:09:44Z cfischer $
#
# Lantronix Remote Configuration Protocol Detection (TCP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108300");
  script_version("$Revision: 8020 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:09:44 +0100 (Thu, 07 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-29 08:03:31 +0100 (Wed, 29 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Lantronix Remote Configuration Protocol Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(30718);

  script_tag(name:"summary", value:"A service supporting the Lantronix remote configuration protocol
  over TCP is running at this host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("host_details.inc");

# partly based on 2012/gb_lantronix_password_disclosure.nasl and
# https://github.com/kost/lantronix-witchcraft/blob/master/lantronix-witchcraft.pl

port = 30718;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# TCP getconfig command
getconf_req = raw_string( 0x00, 0x00, 0x00, 0xF8 );
send( socket:soc, data:getconf_req );
getconf_recv = recv( socket:soc, length:124 );

if( ! getconf_recv || strlen( getconf_recv ) != 124 || hexstr( substr( getconf_recv, 0, 3 ) ) != "000000f9" ) {
  close( soc );
  exit( 0 );
}

# TCP query command
query_req = raw_string( 0x00, 0x00, 0x00, 0xF6 );
send( socket:soc, data:query_req );
query_recv = recv( socket:soc, length:30 );
close( soc );

info = make_array();

# collect IP
for( i = 4; i < 8; i++ ) {
  if( i != 4 ) ip += ".";
  ip += string( ord( getconf_recv[i] ) );
}
info["IP"] = ip;

# collect Gateway
for( i = 16; i < 20; i++ ) {
  if( i != 16 ) gateway += ".";
  gateway += string( ord( getconf_recv[i] ) );
}
info["Gateway"] = gateway;

# collect host bits of the device
info["Host bits"] = hexstr( getconf_recv[10] );

# collect Password
for( i = 12; i < 16; i++ ) {
  pass += getconf_recv[i];
}

if( hexstr( pass ) == "00000000" ) {
  info["Password"] = "No password set/Enhanced Password enabled";
} else {
  pass = bin2string( ddata:pass, noprint_replacement:'' );
  info["Password"] = pass;
  set_kb_item( name:"lantronix_device/lantronix_remote_conf_tcp/" + port + "/password", value:pass );
  set_kb_item( name:"lantronix_device/lantronix_remote_conf/password_gathered", value:TRUE );
}

if( strlen( query_recv ) == 30 ) {

  # collect type of device
  for( i = 8; i < 12; i++ ) {
    type += string( query_recv[i] );
  }
  type = bin2string( ddata:type, noprint_replacement:'' );
  info["Device Type"] = type;

  # collect the MAC address
  for( i = 24; i < 30; i++ ) {
    if( i != 24 ) mac += ":";
    mac += hexstr( query_recv[i] );
  }
  #verify the syntax of the MAC
  if( egrep( pattern:"([0-9a-fA-F:]{17})", string:mac ) ) {
    register_host_detail( name:"MAC", value:mac, desc:"Get the MAC Address via Lantronix remote configuration protocol" );
    replace_kb_item( name:"Host/mac_address", value:mac );
    info["MAC"] = mac;
  }
}

info["Port"] = port + "/tcp";

set_kb_item( name:"lantronix_device/lantronix_remote_conf_tcp/" + port + "/extracted", value:text_format_table( array:info ) );
set_kb_item( name:"lantronix_device/lantronix_remote_conf_tcp/detected", value:TRUE );
set_kb_item( name:"lantronix_device/lantronix_remote_conf_tcp/port", value:port );
set_kb_item( name:"lantronix_device/lantronix_remote_conf_tcp/" + port + "/type", value:"unknown" ); # Type above doesn't match the actual device type
set_kb_item( name:"lantronix_device/lantronix_remote_conf_tcp/" + port + "/version", value:"unknown" );
set_kb_item( name:"lantronix_device/detected", value:TRUE );

register_service( port:port, proto:"lantronix_remote_conf" );

log_message( port:port, data:"A service supporting the Lantronix remote configuration protocol is running at this port." );
exit( 0 );
