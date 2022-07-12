###############################################################################
# OpenVAS Vulnerability Test
# $Id: ftpd_no_cmd.nasl 11018 2018-08-17 07:13:05Z cfischer $
#
# Fake FTP server does not accept any command
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2008 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.80064");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:13:05 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Fake FTP server does not accept any command");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2008 Michel Arboi");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"insight", value:"The remote server advertises itself as being a FTP server, but it does
  not accept any command, which indicates that it may be a backdoor or a proxy.
  Further FTP tests on this port will be disabled to avoid false alerts.");
  script_tag(name:"summary", value:"The remote FTP service is not working properly");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

port = get_ftp_port( default:21 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

r = ftp_recv_line( socket:soc, retry:3 );
if( ! r ) {
  debug_print('No FTP welcome banner on port ', port, '\n');
  # TBD: Why is this commented out? set_kb_item( name:"ftp/" + port + "/broken", value:TRUE );
  set_kb_item( name:"ftp/" + port + "/no_banner", value:TRUE );
  ftp_close( socket:soc );
  exit( 0 );
}
debug_print( level:2, 'Banner = ', r );

if( r =~ '^[45][0-9][0-9] ' || match( string:r, pattern:'Access denied*', icase:TRUE ) ) {
  log_print( level:1, 'FTP server on port ', port, ' is closed\n' );
  set_kb_item( name:"ftp/" + port + "/denied", value:TRUE );
  ftp_close( socket:soc );
  exit( 0 );
}

# Not QUIT, as some servers close the connection without a 2xx code
foreach cmd( make_list( "HELP", "USER ftp" ) ) {
  send( socket:soc, data:cmd + '\r\n' );
  r = ftp_recv_line( socket:soc, retry:3 );
  if( r !~ '[1-5][0-9][0-9][ -]') {
    debug_print( 'FTP server on port ', port, ' answer to ', cmd, ': ', r );
    log_message( port:port );
    set_kb_item( name:"ftp/" + port + "/broken", value:TRUE );
    close( soc );
    exit( 0 );
  }
  debug_print( level:2, 'FTP server on port ', port, ' answer to ', cmd, ': ', r );
}

close( soc );
exit( 0 );
