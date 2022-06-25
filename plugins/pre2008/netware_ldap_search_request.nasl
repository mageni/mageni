###############################################################################
# OpenVAS Vulnerability Test
# $Id: netware_ldap_search_request.nasl 8402 2018-01-12 14:03:40Z cfischer $
#
# Netware LDAP search request
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2004 David Kyger
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
  script_oid("1.3.6.1.4.1.25623.1.0.12104");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Netware LDAP search request");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Kyger");
  script_family("Netware");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_xref(name:"URL", value:"http://support.novell.com/cgi-bin/search/searchtid.cgi?/10077872.htm");

  script_tag(name:"solution", value:"Disable or restrict anonymous binds in LDAP if not required.");

  script_tag(name:"summary", value:"The server's directory base is set to NULL.");

  script_tag(name:"impact", value:"This allows information to be enumerated without any prior
  knowledge of the directory structure.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ldap.inc");
include("misc_func.inc");

port = get_ldap_port( default:389 );

flag = FALSE;

report = 'The following information was pulled from the server via a LDAP request:\n';

senddata = raw_string(
0x30, 0x25, 0x02, 0x01, 0x02, 0x63, 0x20, 0x04, 0x00, 0x0a,
0x01, 0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01,
0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65,
0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00
			);
soc = open_sock_tcp( port );
if ( ! soc ) exit( 0 );

send( socket:soc, data:senddata );
buf = recv( socket:soc, length:4096 );
close( soc );
if( isnull( buf ) ) exit( 0 );

version = string( buf );
hbuf    = hexstr( buf );

if( "Novell" >< buf ) {
  hostname = strstr( hbuf, "4c44415020536572766572" );
  hostname = hostname - strstr( hostname, "304f302b04075665" );
  if( hostname )
    hostname = hex2raw( s:hostname );

  if( hostname ) {
    report += string( "Hostname: ", hostname, "\n" );
    flag = TRUE;
  }
}

if( "LDAP Server" >< buf ) {
  version = strstr( hbuf, "4e6f76656c6c" );
  version = version - strstr( version, "300d" );
  if( version )
    version = hex2raw( s:version );

  if( version ) {
    report += string( "LDAP Server Version: ", version, "\n" );
    flag = TRUE;
  }
}

if( flag ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );