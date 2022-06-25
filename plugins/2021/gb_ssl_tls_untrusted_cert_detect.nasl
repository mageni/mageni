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
  script_oid("1.3.6.1.4.1.25623.1.0.117764");
  script_version("2021-11-12T07:06:08+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2021-11-12 11:32:18 +0000 (Fri, 12 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-09 10:22:58 +0000 (Tue, 09 Nov 2021)");
  script_name("SSL/TLS: Untrusted Certificate Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("gb_ssl_sni_supported.nasl", "gb_tls_version_get.nasl", "gb_starttls_pop3.nasl", "gb_starttls_imap.nasl",
                      "gb_starttls_ftp.nasl", "gb_starttls_smtp.nasl", "gb_postgres_tls_support.nasl", "gb_starttls_ldap.nasl",
                      "gb_starttls_nntp.nasl", "gb_starttls_xmpp.nasl", "gb_starttls_mysql.nasl", "gb_starttls_irc.nasl",
                      "gb_starttls_rdp.nasl", "gb_ssl_tls_cert_chain_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"Checks and reports if a remote SSL/TLS service is using a
  certificate which is untrusted / the verification against the system wide trust store has failed.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

# nb: Available since r29312 (old SVN) of openvas-scanner (means: All currently supported GVM
# versions should have this)
if( ! defined_func( "socket_cert_verify" ) )
  exit( 0 );

include("ssl_funcs.inc");
include("misc_func.inc");
include("mysql.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! get_kb_item( "tls/supported/" + port ) )
  exit( 0 );

# nb: Basically only used for the reporting below but if this doesn't exist it wasn't possible to
# verify the cert anyway...
if( ! server_cert = get_kb_item( "ssl_tls/cert_chain/" + port + "/certs/server_cert" ) )
  exit( 0 );

# nb: If SNI is supported we need to fork on each host name on our own. This is done because
# otherwise socket_negotiate_ssl() would fork internally and after we had called open_ssl_socket()
# which would cause issues with failed connections / socket communication. The fork on the available
# host names needs to be done before doing any socket operation (e.g. opening a socket).
if( get_kb_item( "sni/" + port + "/supported" ) )
  get_host_name();

if( ! soc = open_ssl_socket( port:port ) )
  exit( 0 );

if( ! socket_negotiate_ssl( socket:soc ) )
  exit( 0 );

status = socket_cert_verify( socket:soc );
close( soc );

# nb: From the socket_cert_verify() function description:
# 0 in case of successful verification. A positive integer in case of verification error or NULL on other errors.
if( isnull( status ) ) {
  # nb: We're not getting the info (at least currently) what has failed in the scanners socket_cert_verify() function.
  report = "Failed to verify certificate status due to an unknown error in the scanner.";
}

else if( status > 0 ) {

  if( ! certobj = cert_open( base64_decode( str:server_cert ) ) ) {
    report = "Failed to open server certificate due to an unknown error in the scanner.";
  } else {

    report = 'The remote SSL/TLS server is using the following certificate(s) which failed the verification against the system wide trust store (serial:issuer):\n';

    serial = cert_query( certobj, "serial" );
    if( ! serial )
      serial = "N/A";

    issuer = cert_query( certobj, "issuer" );
    if( ! issuer )
      issuer = "N/A";

    cert_close( certobj );

    report += '\n' + serial + ":" + issuer + " (Server certificate)";

    chain = get_kb_list( "ssl_tls/cert_chain/" + port + "/certs/chain" );
    if( chain ) {

      foreach cert( chain ) {

        if( ! certobj = cert_open( base64_decode( str:cert ) ) )
          continue;

        serial = cert_query( certobj, "serial" );
        if( ! serial )
          serial = "N/A";

        issuer = cert_query( certobj, "issuer" );
        if( ! issuer )
          issuer = "N/A";

        cert_close( certobj );

        report += '\n' + serial + ":" + issuer + " (Certificate in chain)";
      }
    }
  }
}

if( strlen( report ) > 0 )
  log_message( port:port, data:report );

exit( 0 );