###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerberos_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Kerberos Detection (TCP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103854");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-12-12 11:31:47 +0100 (Thu, 12 Dec 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Kerberos Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports(88);

  script_tag(name:"summary", value:"The script sends a connection request to detect a running kerberos server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("byte_func.inc");
include("misc_func.inc");

function parse_resp( res, byte ) {

  local_var res, byte, i, len, realm, stime;

  if( ! res || strlen( res ) < 16 ) return;

  for( i = 4; i < strlen( res ); i++ ) {

    if( res[i] == byte ) {

      i++;
      l = res[i];
      len = ord( l );

      if( ! len || strlen( res ) < len || res[i-3] == '\xA2' ) continue; # \xA2 == ignore ctime

      return substr( res, i + 1, ( i + len ) );

    }
  }
}

function mkd_date_str( rdate ) {

  local_var y, M, d, h, m, s;

  y = substr( rdate, 0, 3 );
  M = substr( rdate, 4, 5 );
  d = substr( rdate, 6, 7 );
  h = substr( rdate, 8, 9 );
  m = substr( rdate, 10, 11 );
  s = substr( rdate, 12, 13 );

  return y + '-' + M + '-' + d + ' ' + h + ':' + m + ':' + s;

}

port = 88;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string(0x00,0x00,0x00,0x7d,0x6a,0x7b,0x30,0x79,0xa1,0x03,0x02,0x01,0x05,0xa2,0x03,0x02,
                 0x01,0x0a,0xa4,0x6d,0x30,0x6b,0xa0,0x07,0x03,0x05,0x00,0x00,0x00,0x00,0x00,0xa2,
                 0x09,0x1b,0x07,0x4f,0x70,0x65,0x6e,0x56,0x41,0x53,0xa3,0x1c,0x30,0x1a,0xa0,0x03,
                 0x02,0x01,0x02,0xa1,0x13,0x30,0x11,0x1b,0x06,0x6b,0x72,0x62,0x74,0x67,0x74,0x1b,
                 0x07,0x4f,0x70,0x65,0x6e,0x56,0x41,0x53,0xa5,0x11,0x18,0x0f,0x32,0x30,0x33,0x37,
                 0x30,0x39,0x31,0x33,0x30,0x32,0x34,0x38,0x30,0x35,0x5a,0xa6,0x11,0x18,0x0f,0x32,
                 0x30,0x33,0x37,0x30,0x39,0x31,0x33,0x30,0x32,0x34,0x38,0x30,0x35,0x5a,0xa7,0x04,
                 0x02,0x02,0x5b,0xa1,0xa8,0x0b,0x30,0x09,0x02,0x01,0x12,0x02,0x01,0x11,0x02,0x01,
                 0x17);

send( socket:soc, data:req );

buf = recv( socket:soc, length:4 );
if( buf == NULL ) {
  close(soc);
  exit( 0 );
}

len = getdword( blob:buf, pos:0 );
if( len > 65535 ) exit( 0 );

res = recv( socket:soc, length:len );
if( res == NULL ) {
  close( soc );
  exit( 0 );
}

# 0x7e == KRB-ERROR
if( ! res || res[0] != '\x7e' ) {
  close( soc );
  exit( 0 );
}

register_service( port:port, ipproto:"tcp", proto:'kerberos' );

stime = parse_resp( res:res, byte:'\x18' );

req = raw_string(0x00,0x00,0x00,0x59,0x6a,0x57,0x30,0x55,0xa1,0x03,0x02,0x01,0x05,0xa2,0x03,0x02,
                 0x01,0x0a,0xa4,0x49,0x30,0x47,0xa0,0x07,0x03,0x05,0x00,0x40,0x00,0x00,0x10,0xa2,
                 0x09,0x1b,0x07,0x4f,0x70,0x65,0x6e,0x56,0x41,0x53,0xa5,0x11,0x18,0x0f,0x32,0x30,
                 0x33,0x37,0x30,0x39,0x31,0x33,0x30,0x32,0x34,0x38,0x30,0x35,0x5a,0xa6,0x11,0x18,
                 0x0f,0x32,0x30,0x33,0x37,0x30,0x39,0x31,0x33,0x30,0x32,0x34,0x38,0x30,0x35,0x5a,
                 0xa7,0x04,0x02,0x02,0x1f,0x02,0xa8,0x05,0x30,0x03,0x02,0x01,0x0b);

send( socket:soc, data:req );

buf = recv( socket:soc, length:4 );

if( buf != NULL ) {

  len = getdword(blob:buf, pos:0);

  if( len < 65535 && len > 0) {

    res = recv( socket:soc, length:len );
    close( soc );

    if( res[0] == '\x7e' ) {
      realm = parse_resp( res:res, byte:'\x1b' );
    }
  }
} else {
  close( soc );
}

report = 'A Kerberos Server is running at this port.\n';

if( realm ) report += '\nRealm: ' + realm;

if( stime ) report += '\nServer time: ' + mkd_date_str( rdate:stime ) + '\n';

set_kb_item( name:"kerberos/detected", value:TRUE );
log_message( port:port, data:report );

exit( 0 );