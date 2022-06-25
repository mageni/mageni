# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117810");
  script_version("2021-12-07T07:21:34+0000");
  script_tag(name:"last_modification", value:"2021-12-07 11:00:26 +0000 (Tue, 07 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-06 13:43:24 +0000 (Mon, 06 Dec 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SSL/TLS: Client Certificate Required");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("gb_tls_version_get.nasl", "gb_ssl_sni_supported.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"The remote SSL/TLS service requires an SSL/TLS client
  certificate.");

  script_tag(name:"vuldetect", value:"Sends multiple connection requests to the remote SSL/TLS
  service and attempts to determine if the service requires an SSL/TLS client certificate.");

  exit(0);
}

include("ssl_funcs.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("mysql.inc");
include("byte_func.inc");
include("dump.inc");

# nb: See e.g. the following for some background:
# https://datatracker.ietf.org/doc/html/rfc5246#section-7.4
# https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.4
function get_tls_cert_req_record( ssl_tls_version, port ) {

  local_var ssl_tls_version, port;
  local_var soc, hello, data, record;

  if( ! ssl_tls_version || ! port )
    return FALSE;

  if( ! soc = open_ssl_socket( port:port ) )
    return FALSE;

  hello = ssl_hello( port:port, version:ssl_tls_version );
  if( ! hello ) {
    close( soc );
    return FALSE;
  }

  send( socket:soc, data:hello );

  while( TRUE ) {

    data = ssl_recv( socket:soc );
    if( ! data ) {
      close( soc );
      return FALSE;
    }

    # nb: No need to continue if we have received an Alert.
    if( search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) ) ) {
      close( soc );
      return FALSE;
    }

    # nb: This is what we're looking for.
    record = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_CERTIFICATE_REQUEST ) );
    if( record ) {
      close( soc );
      return record;
    }

    # nb: Also no need to continue if we have reached the Server Hello Done.
    if( search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) ) ) {
      close( soc );
      return FALSE;
    }
  }

  # nb: We shouldn't arrive here as we normally should always match any of the returns above but
  # we're still closing the socket just to be sure.
  close( soc );
  return FALSE;
}

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! ssl_tls_versions = get_supported_tls_versions( port:port, min:SSL_v3 ) )
  exit( 0 );

# nb: Used later for doing the reporting
req_cert_list = make_list();

foreach ssl_tls_version( ssl_tls_versions ) {

  record = get_tls_cert_req_record( port:port, ssl_tls_version:ssl_tls_version );
  if( ! record )
    continue;

  # nb: Another verification just to be sure...
  if( record["handshake_typ"] == SSLv3_CERTIFICATE_REQUEST &&
      record["content_typ"] == SSLv3_HANDSHAKE ) {
    cert_required = TRUE;
    req_cert_list = make_list( req_cert_list, version_string[ssl_tls_version] );    
  }
}

if( cert_required ) {

  report = 'The remote SSL/TLS service requires a client certificate when accessing it via the following SSL/TLS protocol version(s):\n';

  # Sort to not report changes on delta reports if just the order is different
  req_cert_list = sort( req_cert_list );
  foreach req_cert_item( req_cert_list )
    report += '\n' + req_cert_item;

  log_message( port:port, data:report );
}

exit( 0 );