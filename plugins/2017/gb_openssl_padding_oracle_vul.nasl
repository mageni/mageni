###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_padding_oracle_vul.nasl 12865 2018-12-21 10:51:07Z cfischer $
#
# SSL/TLS: OpenSSL 'CVE-2016-2107' Padding Oracle Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.107141");
  script_version("$Revision: 12865 $");
  script_cve_id("CVE-2016-2107");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 11:51:07 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-03-30 12:21:46 +0100 (Thu, 30 Mar 2017)");
  script_name("SSL/TLS: OpenSSL 'CVE-2016-2107' Padding Oracle Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_tls_version_get.nasl");
  script_family("SSL and TLS");
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160503.txt");

  script_tag(name:"summary", value:"This host is installed with OpenSSL and is prone to padding oracle attack.");

  script_tag(name:"vuldetect", value:"Send an encrypted padded message and check the returned alert (Record Overflow
  if vulnerable, Bad Record Mac if no vulnerable.");

  script_tag(name:"insight", value:"The vulnerability is due to not considering memory allocation during a certain
  padding check.");

  script_tag(name:"impact", value:"Exploiting this vulnerability allows remote attackers to obtain sensitive cleartext
  information via a padding oracle attack against an AES CBC session.");

  script_tag(name:"affected", value:"OpenSSL before 1.0.1t and 1.0.2 before 1.0.2h.");

  script_tag(name:"solution", value:"OpenSSL 1.0.2 users should upgrade to 1.0.2h.

  OpenSSL 1.0.1 users should upgrade to 1.0.1t.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("mysql.inc"); # For recv_mysql_server_handshake() in open_ssl_socket()
include("misc_func.inc");
include("byte_func.inc");
include("ssl_funcs.inc");

if(  defined_func( 'prf_sha256' ) &&
     defined_func( 'tls1_prf' )   &&
     defined_func( 'rsa_public_encrypt' ) &&
     defined_func( 'aes128_cbc_encrypt' )
  )
{
  if( ! port = get_ssl_port() )
    exit( 0 );

  if( ! sslversion = get_supported_tls_version( port:port, min:TLS_10, max:TLS_12 ) )
    exit( 0 );

  protocolversion = TLS_12;

  MASTER_SECRET_LABEL = "master secret";
  CLIENT_FINISHED_LABEL = "client finished";
  KEY_EXPANSION_LABEL = "key expansion";

  CHANGE_CIPHER_SPEC_LENGTH = raw_string( 0x00, 0x01 );
  CHANGE_CIPHER_SPEC_MESSAGE = raw_string( 0x01 );

  RANDOM = 28;
  UNIX_TIME = 4;
  PREMASTER_SECRET = 48;
  MASTER_SECRET = 48;
  SECRET_SET_SIZE = 72;

  selectedCipherSuite = sslv3_tls_raw_ciphers['TLS_RSA_WITH_AES_128_CBC_SHA'];

  if( ! soc = open_ssl_socket( port:port ) )
    exit( 0 );

  clientRandom = raw_string( dec2hex( num:unixtime() ) ) + raw_string( rand_str( length:RANDOM ) );

  hello = ssl_hello( version:sslversion, ciphers:selectedCipherSuite, random:clientRandom, handshake_version:protocolversion, add_tls_renegotiation_info:FALSE );

  if( ! hello ) {
    close( soc );
    exit( 0 );
  }

  send( socket:soc, data:hello );

  hello_done = FALSE;

  while ( ! hello_done ) {
    data = ssl_recv( socket:soc );
    if( ! data ) {
      close( soc );
      exit( 0 );
    }

    serverhello = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );

    if( serverhello ) {
      serverUnixTime = serverhello['time'];
      serverUnixTimehex = dec2hex(num:serverUnixTime);
      serverUnixTime = raw_string(serverUnixTimehex);
      randomserver = serverhello['random'];
      sessionId = serverhello['session_id'];
      sessionIdLength = serverhello['session_id_len'];
      selectedCipher = mkword( serverhello['cipher_spec'] );
    }

    certificate = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_CERTIFICATE ) );
    if( certificate ) {
      foreach cert ( certificate['cert_list'] ) {
        if( ! certobj = cert_open( cert ) )
          continue;

        modulus = cert_query( certobj, "modulus" );
        exponent = cert_query( certobj, "exponent" );

        if( modulus )
          modulus = substr( modulus, 1 );

        if( modulus && exponent )
          break;
      }
    }

    serverhellodone = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );

    if( serverhellodone ) {
      hello_done = TRUE;
      break;
    }
  }

  if( ! modulus ) {
    close( soc );
    exit( 0 );
  }

  keyByteLength = strlen( modulus );
  randomByteLength = keyByteLength - PREMASTER_SECRET - 3;
  padding = crap( data:raw_string( 0x03), length:randomByteLength );

  need = (PREMASTER_SECRET - 2) * 8;

  premasterSecret = protocolversion + bn_random( need:need );

  PlainPaddedPremasterSecret = raw_string( 0x00, 0x02 ) + padding  + raw_string( 0x00 ) + premasterSecret;

  paddedPremasterSecret = PlainPaddedPremasterSecret;

  random_length = 2 * (RANDOM + UNIX_TIME) ;

  serverrandom = serverUnixTime + randomserver;

  random = clientRandom + serverrandom;

  mastersecret = prf_sha256( secret:premasterSecret, seed:random, label:MASTER_SECRET_LABEL , outlen:MASTER_SECRET );

  encrypted = rsa_public_encrypt( data:paddedPremasterSecret, e:exponent, n:modulus, pad:FALSE );

  ##Sending ClientKeyExchange message

  Premaster_length = data_len( data:encrypted );

  ckedata =  data_len( data:encrypted ) + encrypted;

  hdlen = raw_string( 0x00 ) + data_len( data:ckedata );
  data = raw_string( SSLv3_CLIENT_KEY_EXCHANGE ) + hdlen + ckedata;
  cke_len = data_len( data:data );

  cke = raw_string( SSLv3_HANDSHAKE ) + protocolversion + cke_len + data;

  ehashmsg  = raw_string( SSLv3_HANDSHAKE ) + protocolversion + data_len( data:mastersecret ) + mastersecret;

  KeySize = 16;

  readMacsize = 20;
  writeMacsize = 20;

  random = serverrandom + clientRandom ;

  keyBlock = prf_sha256( secret:mastersecret, seed:random, label:KEY_EXPANSION_LABEL, outlen:SECRET_SET_SIZE );

  offset = 0;

  for( i = offset; i < readMacsize; i++ ) {
    clientMacWriteSecret+= keyBlock[i];
  }

  offset += readMacsize;

  for( i = offset; i < offset + writeMacsize; i++ ) {
    serverMacWriteSecret += keyBlock[i];
  }

  offset += writeMacsize;

  for( i = offset; i < offset + KeySize; i++ ) {
    clientWriteKey += keyBlock[i];
  }

  offset+=KeySize;

  for( i = offset; i < offset+KeySize; i++ ) {
    serverWriteKey += keyBlock[i];
  }

  #generate IV:
  need = 16 * 8;
  clientWriteIv = bn_random( need:need );
  serverWriteIv = bn_random( need:need );

  need = 32 * 8;
  handshakeMessagesHash = bn_random( need:need );

  datatoencrypt = crap( length:32, data:raw_string( 0x3f ) );

  encdata1 = aes128_cbc_encrypt( data:datatoencrypt, key:clientWriteKey, iv:clientWriteIv );

  encdata = clientWriteIv + encdata1;

  ehashmsg  = raw_string( SSLv3_HANDSHAKE ) + protocolversion + data_len( data:encdata ) + encdata;

  ccs = raw_string( SSLv3_CHANGECIPHERSPEC ) + protocolversion + CHANGE_CIPHER_SPEC_LENGTH + CHANGE_CIPHER_SPEC_MESSAGE;

  datatosend = cke + ccs + ehashmsg;

  send( socket:soc, data:datatosend );

  clkechange_done = FALSE;

  while( ! clkechange_done ) {
    data = ssl_recv( socket:soc );
    if( ! data ) {
      close( soc );
      exit( 0 );
    }

    record = search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) );
    if( record ) {
      close( soc );
      if( record['level'] == SSLv3_ALERT_FATAL && record['description'] == SSLv3_ALERT_RECORD_OVERFLOW ) {
        report = "It was possible to send an encrypted data with malformed padding and receive Record Overflow alert from the SSL Server";
        security_message( port:port, data:report );
        exit( 0 );
      }
      exit( 99 );
    }

    record = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
    if( record ) {
      clkechange_done = TRUE;
      break;
    }
  }

  if ( soc )
    close( soc );
}

exit( 0 );