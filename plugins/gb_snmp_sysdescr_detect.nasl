# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103416");
  script_version("2021-03-25T09:28:08+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-03-25 09:28:08 +0000 (Thu, 25 Mar 2021)");
  script_tag(name:"creation_date", value:"2012-02-14 10:07:41 +0100 (Tue, 14 Feb 2012)");
  script_name("SNMP sysDescr Detection and Reporting");
  script_category(ACT_SETTINGS);
  script_family("SNMP");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("snmp_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected");

  script_tag(name:"summary", value:"SNMP based detection and reporting of the sysDescr
  (OID: 1.3.6.1.2.1.1.1.0) gathered from the remote device.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("snmp_func.inc");

function parse_result( data ) {

  local_var data;
  local_var v, ok, oid_len, tmp;

  if( ! data || strlen( data ) < 8 )
    return FALSE;

  for( v = 0; v < strlen( data ); v++ ) {
    if( ord( data[v] ) == 43 && ord( data[v-1] ) == 8 ) {
      ok = TRUE;
      break;
    }
    oid_len = ord( data[v] );
  }

  if( ! ok || oid_len < 8 )
    return FALSE;

  tmp = substr( data, ( v + oid_len + 2 ) );

  if( ! isprint( c:tmp[0] ) )
    tmp = substr( tmp, 1, strlen( tmp ) - 1 );

  return tmp;
}

oid = "1.3.6.1.2.1.1.1.0";
report = 'The following SNMP sysDescr (OID: ' + oid + ') was extracted from the remote device:\n\n';

port = snmp_get_port( default:161 );

if( defined_func( "snmpv3_get" ) ) {

  if( ! res = snmp_get( port:port, oid:oid ) )
    exit( 0 );

  set_kb_item( name:"SNMP/" + port + "/sysdescr", value:res );
  set_kb_item( name:"SNMP/sysdescr/available", value:TRUE );

  log_message( port:port, data:report + res, proto:"udp" );

  exit( 0 );

} else {

  community = snmp_get_community( port:port );
  if( ! community )
    community = "public";

  soc = open_sock_udp( port );
  if( ! soc )
    exit( 0 );

  SNMP_BASE = 31;
  COMMUNITY_SIZE = strlen( community );

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
    if( ! result || ord( result[0] ) != 48 )
      continue;

    if( res = parse_result( data:result ) ) {

      close( soc );

      set_kb_item( name:"SNMP/" + port + "/sysdescr", value:res );
      set_kb_item( name:"SNMP/sysdescr/available", value:TRUE );

      log_message( port:port, data:report + res, proto:"udp" );
      exit( 0 );
    }
  }
  close( soc );
}

exit( 0 );
