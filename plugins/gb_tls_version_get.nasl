###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tls_version_get.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# SSL/TLS: Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105782");
  script_version("$Revision: 12413 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-29 10:54:20 +0200 (Wed, 29 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("secpod_open_tcp_ports.nasl", "gb_starttls_pop3.nasl", "gb_starttls_imap.nasl", "gb_starttls_ftp.nasl", "gb_starttls_smtp.nasl",
                      "gb_postgres_tls_support.nasl", "gb_starttls_ldap.nasl", "gb_starttls_nntp.nasl", "gb_starttls_xmpp.nasl", "gb_starttls_mysql.nasl",
                      "gb_starttls_irc.nasl", "gb_starttls_rdp.nasl", "gb_dont_scan_fragile_device.nasl");
  script_mandatory_keys("TCP/PORTS");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the SSL/TLS version number from the reply. The Result is stored in the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("mysql.inc"); # For recv_mysql_server_handshake() in open_ssl_socket()
include("ssl_funcs.inc");
include("byte_func.inc");
include("misc_func.inc");

# nb: Don't use get_all_tcp_ports() as we only want to exclude
# specific ports from the TLS checks defined in gb_dont_scan_fragile_device.nasl
port = get_kb_item( "TCP/PORTS" );
if( ! port || ! get_port_state( port ) ) exit( 0 );

# nb: Set by gb_dont_scan_fragile_device.nasl. Some devices are even crashing
# if we're touching one or more ports of them with our SSL/TLS checks so those
# ports gets excluded here.
if( get_kb_item( "fragile_port/exclude_tls/" + port ) ) exit( 0 );

sup_tls = ''; # nb: To make openvas-nasl-lint happy...

foreach vers( make_list( TLS_10, TLS_11, TLS_12, SSL_v2, SSL_v3 ) )
{
  soc = open_ssl_socket( port:port );
  if( ! soc ) continue;

  hello = ssl_hello( version:vers );
  if( ! hello )
  {
    close( soc );
    continue;
  }

  send( socket:soc, data:hello );

  data = ssl_recv( socket:soc );
  if( ! data )
  {
    close( soc );
    continue;
  }

  if( vers == SSL_v2 )
    search = make_array( "content_typ", SSLv2_SERVER_HELLO );
  else
    search = make_array( "handshake_typ", SSLv3_SERVER_HELLO );

  record = search_ssl_record( data:data, search:search );

  if( vers == SSL_v2 )
  {
    if( int( record['cipher_spec_len'] ) < 1 )
    {
      close( soc );
      continue;
    }
  }

  close( soc );

  if( ! record ) continue;

  if( isnull( record['version'] ) ) continue;

  if( record['version'] == vers)
  {
    set_kb_item( name:"tls_version_get/" + port + "/version", value:version_string[vers]);
    set_kb_item( name:"tls_version_get/" + port + "/hex_version", value:hexstr(record['version']));
    set_kb_item( name:"tls_version_get/" + port + "/raw_version", value:record['version']);
    sup_tls += version_string[vers] + ';';
  }
}

if(strlen(sup_tls))
{
  sup_tls = ereg_replace(string:sup_tls, pattern:"(;)$", replace:"");
  set_kb_item( name:'tls/supported/' + port, value:sup_tls );
  set_kb_item( name:"ssl_tls/port", value:port );
}

exit(0);
