###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_mysql.nasl 11915 2018-10-16 08:05:09Z cfischer $
#
# SSL/TLS: MySQL / MariaDB (STARTTLS-like) SSL/TLS Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108071");
  script_version("$Revision: 11915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 10:05:09 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"creation_date", value:"2017-02-06 11:18:02 +0100 (Mon, 06 Feb 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: MySQL / MariaDB (STARTTLS-like) SSL/TLS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL_MariaDB/installed");

  script_tag(name:"summary", value:"Checks if the remote MySQL / MariaDB server supports (STARTTLS-like) SSL/TLS.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://dev.mysql.com/doc/internals/en/ssl.html");

  exit(0);
}

include("mysql.inc");
include("ssl_funcs.inc");
include("byte_func.inc");
include("misc_func.inc");

# https://dev.mysql.com/doc/internals/en/ssl.html
# SSL Request Packet with the CLIENT_SSL capability enabled
req = raw_string( 0x20, 0x00, 0x00, 0x01, 0x05, 0xae, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00 );

port = get_kb_item( "Services/mysql" );
if( ! port ) port = 3306;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

buf = recv_mysql_server_handshake( soc:soc );

send( socket:soc, data:req );

hello = ssl_hello();
send( socket:soc, data:hello );

hello_done = FALSE;

while( ! hello_done ) {

  buf = ssl_recv( socket:soc );

  # MySQL/MariaDB will close the connection instead of sending a SSLv3_ALERT
  if( ! buf ) {
    close( soc );
    exit( 0 );
  }

  record = search_ssl_record( data:buf, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
  if( record ) {
    hello_done = TRUE;
    break;
  }
}

close( soc );

if( hello_done ) {
  set_kb_item( name:"mysql/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"mysql" );
  log_message( port:port, data:"The remote MySQL / MariaDB server supports (STARTTLS-like) SSL/TLS." );
}

exit( 0 );