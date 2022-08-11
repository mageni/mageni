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
  script_oid("1.3.6.1.4.1.25623.1.0.117757");
  script_version("2021-10-28T09:43:03+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-27 11:26:49 +0000 (Wed, 27 Oct 2021)");
  script_name("SSL/TLS: Safe/Secure Renegotiation Support Status");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("gb_ssl_sni_supported.nasl", "gb_tls_version_get.nasl", "gb_starttls_pop3.nasl", "gb_starttls_imap.nasl",
                      "gb_starttls_ftp.nasl", "gb_starttls_smtp.nasl", "gb_postgres_tls_support.nasl", "gb_starttls_ldap.nasl",
                      "gb_starttls_nntp.nasl", "gb_starttls_xmpp.nasl", "gb_starttls_mysql.nasl", "gb_starttls_irc.nasl",
                      "gb_starttls_rdp.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://www.gnutls.org/manual/html_node/Safe-renegotiation.html");
  script_xref(name:"URL", value:"https://wiki.openssl.org/index.php/TLS1.3#Renegotiation");

  script_tag(name:"summary", value:"Checks and reports if a remote SSL/TLS service supports
  safe/secure renegotiation.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

# nb: Available since GOS 21.04.9 / openvas-scanner 21.4.4
if( ! defined_func( "socket_check_ssl_safe_renegotiation" ) )
  exit( 0 );

include("ssl_funcs.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("mysql.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! get_kb_item( "tls/supported/" + port ) )
  exit( 0 );

# nb: We're not using get_supported_tls_versions() from ssl_func.inc here on purpose because we want
# to check all known / current SSL/TLS versions supported by the scanner including failed
# connections to the remote service for specific SSL/TLS versions.
#
# nb: Check should start with SSLv3 and (currently) end with the highest available TLSv1.3. Note
# TLSv1.3 generally doesn't support renegotiation according to:
# https://wiki.openssl.org/index.php/TLS1.3#Renegotiation
transports[ENCAPS_SSLv3] = "SSLv3";
transports[ENCAPS_TLSv1] = "TLSv1.0";
transports[ENCAPS_TLSv11] = "TLSv1.1";
transports[ENCAPS_TLSv12] = "TLSv1.2";
transports[ENCAPS_TLSv13] = "TLSv1.3";

# nb: Used later for doing the reporting
info = make_array();

# nb: Used to only launch VTs which require that this VT was able to determine the status
set_kb_item( name:"ssl_tls/safe_secure_renegotiation/checked", value:TRUE );

# nb: If SNI is supported we need to fork on each host name on our own. This is done because
# otherwise socket_negotiate_ssl() would fork internally and after we had called open_ssl_socket()
# which would cause issues with failed connections / socket communication. The fork on the available
# host names needs to be done before doing any socket operation (e.g. opening a socket).
if( get_kb_item( "sni/" + port + "/supported" ) )
  get_host_name();

foreach transport_num( keys( transports ) ) {

  transport_name = transports[transport_num];

  if( ! soc = open_ssl_socket( port:port ) ) {
    set_kb_item( name:"ssl_tls/safe_secure_renegotiation/" + port + "/" + tolower( transport_name ) + "/status", value:"unknown_no_socket" );
    info[transport_name] = "Unknown, Reason: Failed to open a socket to the remote service.";
    continue;
  }

  if( ! soc = socket_negotiate_ssl( socket:soc, transport:transport_num ) ) {
    set_kb_item( name:"ssl_tls/safe_secure_renegotiation/" + port + "/" + tolower( transport_name ) + "/status", value:"unknown_no_negotiation" );
    info[transport_name] = "Unknown, Reason: Scanner failed to negotiate an SSL/TLS connection (Either the scanner or the remote host is probably not supporting / accepting this SSL/TLS protocol version).";
    continue;
  }

  status = socket_check_ssl_safe_renegotiation( socket:soc );
  close( soc );

  # nb: From the function description:
  # 1 if supported, 0 otherwise. Null or -1 on error.
  if( status == 1 ) {
    set_kb_item( name:"ssl_tls/safe_secure_renegotiation/" + port + "/" + tolower( transport_name ) + "/status", value:"enabled" );
    info[transport_name] = "Enabled, Note: While the remote service announces the support of safe/secure renegotiation it still might not support / accept renegotiation at all.";
  }

  else if( isnull( status ) || status < 0 ) {
    set_kb_item( name:"ssl_tls/safe_secure_renegotiation/" + port + "/" + tolower( transport_name ) + "/status", value:"unknown" );
    info[transport_name] = "Unknown, Reason: An unknown error occurred in the scanner while determining the status.";
  }

  else if( status == 0 ) {
    set_kb_item( name:"ssl_tls/safe_secure_renegotiation/" + port + "/" + tolower( transport_name ) + "/status", value:"disabled" );
    if( transport_name == "TLSv1.3" )
      info[transport_name] = "Disabled (The " + transport_name + " protocol generally doesn't support renegotiation so this is always reported as 'Disabled')";
    else
      info[transport_name] = "Disabled";
  }

  # nb: Shouldn't happen but we're still checking it like this just to be sure...
  else {
    set_kb_item( name:"ssl_tls/safe_secure_renegotiation/" + port + "/" + tolower( transport_name ) + "/status", value:"unknown" );
    info[transport_name] = "Unknown, Reason: An unknown error occurred in the scanner while determining the status.";
  }
}

report = text_format_table( array:info, sep:" | ", columnheader:make_list( "Protocol Version", "Safe/Secure Renegotiation Support Status" ) );
log_message( port:port, data:report );

exit( 0 );