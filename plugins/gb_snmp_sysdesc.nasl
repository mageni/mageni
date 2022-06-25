###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snmp_sysdesc.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Get SysDescription via SNMP
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103416");
  script_version("$Revision: 10894 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-02-14 10:07:41 +0100 (Tue, 14 Feb 2012)");
  script_name("Get SysDescription via SNMP");
  script_category(ACT_SETTINGS);
  script_family("SNMP");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("snmp_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected");

  script_tag(name:"summary", value:"This NVT get the SysDesc via SNMP and store the result in the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("snmp_func.inc");

function parse_result( data ) {

  local_var data, v, ok, oid_len, tmp;

  if( strlen( data ) < 8 ) return FALSE;

  for( v = 0; v < strlen( data ); v++ ) {
    if( ord( data[v] ) == 43 && ord( data[v-1] ) == 8 ) {
      ok = TRUE;
      break;
    }
    oid_len = ord(data[v]);
  }

  if( ! ok || oid_len < 8 ) return FALSE;

  tmp = substr( data, ( v + oid_len + 2 ) );

  if( ! isprint( c:tmp[0] ) ) {
    tmp = substr( tmp, 1, strlen( tmp ) - 1 );
  }
  return tmp;
}

port = get_snmp_port( default:161 );

if( defined_func( "snmpv3_get" ) ) {

  if( ! res = snmp_get( port:port, oid:'1.3.6.1.2.1.1.1.0' ) ) exit( 0 );

  set_kb_item( name:"SNMP/" + port + "/sysdesc", value:res );
  set_kb_item( name:"SNMP/sysdesc/available", value:TRUE );
  exit( 0 );

} else {

  community = snmp_get_community( port:port );
  if( ! community ) community = "public";

  soc = open_sock_udp( port );
  if( ! soc ) exit( 0 );

  SNMP_BASE = 31;
  COMMUNITY_SIZE = strlen(community);

  sz = COMMUNITY_SIZE % 256;

  len = SNMP_BASE + COMMUNITY_SIZE;
  len_hi = len / 256;
  len_lo = len % 256;

  for( i = 0; i < 3; i++ ) {

    sendata = raw_string( 0x30, 0x82, len_hi, len_lo,
                          0x02, 0x01, i, 0x04, sz );

    sendata += community +
               raw_string( 0xA1, 0x18, 0x02,
                           0x01, 0x01, 0x02, 0x01,
                           0x00, 0x02, 0x01, 0x00,
                           0x30, 0x0D, 0x30, 0x82,
                           0x00, 0x09, 0x06, 0x05,
                           0x2B, 0x06, 0x01, 0x02,
                           0x01, 0x05, 0x00 );

    send( socket:soc, data:sendata );
    result = recv( socket:soc, length:400, timeout:1 );

    if( isnull( result ) || ord( result[0] ) != 48 ) continue;

    if( res = parse_result( data:result ) ) {
      set_kb_item( name:"SNMP/" + port + "/sysdesc", value:res );
      set_kb_item( name:"SNMP/sysdesc/available", value:TRUE );
      close( soc );
      exit( 0 );
    }
  }
  close( soc );
}

exit( 0 );
