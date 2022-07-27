###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_ccs_67899.nasl 12865 2018-12-21 10:51:07Z cfischer $
#
# SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105042");
  script_version("$Revision: 12865 $");
  script_bugtraq_id(67899);
  script_cve_id("CVE-2014-0224");
  script_name("SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 11:51:07 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2014-06-10 17:18:54 +0200 (Tue, 10 Jun 2014)");
  script_category(ACT_ATTACK);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67899");
  script_xref(name:"URL", value:"http://openssl.org/");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow attackers to obtain
  sensitive information by conducting a man-in-the-middle attack. This may lead to other attacks.");

  script_tag(name:"vuldetect", value:"Send two SSL ChangeCipherSpec request and check the response.");

  script_tag(name:"insight", value:"OpenSSL does not properly restrict processing of ChangeCipherSpec
  messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in
  certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive
  information, via a crafted TLS handshake, aka the 'CCS Injection' vulnerability.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"OpenSSL is prone to security-bypass vulnerability.");

  script_tag(name:"affected", value:"OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m and 1.0.1 before 1.0.1h.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("mysql.inc"); # For recv_mysql_server_handshake() in open_ssl_socket()
include("byte_func.inc");
include("ssl_funcs.inc");
include("misc_func.inc");

function _test( v, port ) {

  local_var v, port, soc, hello, data, record, hello_done, req;

  if( ! v ) return FALSE;

  soc = open_ssl_socket( port:port );
  if( ! soc ) return FALSE;

  hello = ssl_hello( version:v );
  if( ! hello ) {
    close( soc );
    return FALSE;
  }

  send( socket:soc, data:hello );

  while( ! hello_done ) {
    data = ssl_recv( socket:soc );
    if( ! data ) {
      close( soc );
      return FALSE;
    }

    record = search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) );
    if( record ) {
      close( soc );
      return FALSE;
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

  req = raw_string( 0x14 ) + v + raw_string( 0x00, 0x01, 0x01 );
  send( socket:soc, data:req );

  data = ssl_recv( socket:soc );

  if( ! data && socket_get_error( soc ) == ECONNRESET ) {
    close( soc );
    return FALSE;
  }

  if( data ) {
    record = search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) );
    if( record ) {
      close( soc );
      return FALSE;
    }
  }

  send( socket:soc, data:req );
  data = ssl_recv( socket:soc );

  close( soc );

  if( ! data ) return FALSE;

  record = search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) );
  if( record ) {
    if( record['level'] == SSLv3_ALERT_FATAL && ( record['description'] == SSLv3_ALERT_BAD_RECORD_MAC || record['description'] == SSLv3_ALERT_DECRYPTION_FAILED ) ) {
      security_message( port:port );
      exit( 0 );
    }
  }
}

port = get_ssl_port();
if( ! port ) exit( 0 );

if( ! versions = get_supported_tls_versions( port:port, min:SSL_v3, max:TLS_12 ) ) exit( 0 );

foreach version( versions ) {
  _test( v:version, port:port );
}

exit( 99 );