# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117951");
  script_version("2022-02-01T10:00:18+0000");
  script_tag(name:"last_modification", value:"2022-02-02 11:01:49 +0000 (Wed, 02 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 08:12:54 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Local Mail Transfer Protocol (LMTP) Service Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/lmtp", 24);

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc2033");

  script_tag(name:"summary", value:"Detection of services supporting the Local Mail Transfer
  Protocol (LMTP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
# nb: For LMTP we can use a few SMTP functions as both protocols behaves quite similar
include("smtp_func.inc");

port = service_get_port( default:24, proto:"lmtp" );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

banner = smtp_recv_line( socket:soc, retry:1 );
banner = chomp( banner );
if( ! banner ) {
  close( soc );
  exit( 0 );
}

# nb: We're using a LHLO so that we're not wrongly detection SMTP as LMTP...
send( socket:soc, data:'LHLO ' + smtp_get_helo_from_kb( port:port ) + '\r\n' );
lhlo = smtp_recv_line( socket:soc, code:"250" );
lhlo = chomp( lhlo );
if( ! lhlo ) {
  close( soc );
  exit( 0 );
}

if( service_is_unknown( port:port ) )
  service_register( port:port, proto:"lmtp", message:"An LMTP server seems to be running on this port." );

set_kb_item( name:"lmtp/banner/available", value:TRUE );
set_kb_item( name:"lmtp/" + port + "/banner", value:banner );
set_kb_item( name:"lmtp/fingerprints/" + port + "/lhlo_banner", value:lhlo );

send( socket:soc, data:'HELP\r\n' );
help = smtp_recv_line( socket:soc );
help = chomp( help );
if( help )
  set_kb_item( name:"lmtp/fingerprints/" + port + "/help_banner", value:help );

send( socket:soc, data:'NOOP\r\n' );
noop = smtp_recv_line( socket:soc );
noop = chomp( noop );
if( noop )
  set_kb_item( name:"lmtp/fingerprints/" + port + "/noop_banner", value:noop );

send( socket:soc, data:'RSET\r\n' );
rset = smtp_recv_line( socket:soc );
rset = chomp( rset );
if( rset )
  set_kb_item( name:"lmtp/fingerprints/" + port + "/rset_banner", value:rset );

send( socket:soc, data:'QUIT\r\n' );
quit = smtp_recv_line( socket:soc );
quit = chomp( quit );
if( quit )
  set_kb_item( name:"lmtp/fingerprints/" + port + "/quit_banner", value:quit );

# nb: Don't use smtp_close() as we want to get the QUIT banner above.
close( soc );

# 220 8a3d01d704b5 LMTP Server (JAMES Protocols Server) ready
if( "LMTP Server (JAMES Protocols Server) ready" >< banner ) {
  set_kb_item( name:"lmtp/apache/james_server/detected", value:TRUE );
  set_kb_item( name:"lmtp/" + port + "/apache/james_server/detected", value:TRUE );
  guess += '\n- Apache James';
}

# 220 $hostname Zimbra LMTP server ready
# 220 $hostname Zimbra LMTP ready
if( banner =~ "Zimbra LMTP (server )?ready" ) {
  set_kb_item( name:"lmtp/zimbra/detected", value:TRUE );
  set_kb_item( name:"lmtp/" + port + "/zimbra/detected", value:TRUE );
  guess += '\n- Zimbra';

  # Zimbra runs only on Unix-like systems. We have added here for now but should write a dedicated
  # LMTP OS Detection VT if more of such OS pattern are getting added to this VT.
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:"LMTP banner", port:port, banner:banner, desc:"Local Mail Transfer Protocol (LMTP) Service Detection", runs_key:"unixoide" );
}

# 220 $hostname DBMail LMTP service ready to rock
if( banner =~ "DBMail LMTP service" ) {
  set_kb_item( name:"lmtp/dbmail/detected", value:TRUE );
  set_kb_item( name:"lmtp/" + port + "/dbmail/detected", value:TRUE );
  guess += '\n- DBMail';
}

report = 'Remote LMTP server banner:\n\n' + banner;
if( strlen( guess ) > 0 )
  report += '\n\nThis is probably:\n' + guess;

log_message( port:port, data:report );