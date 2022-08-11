###############################################################################
# OpenVAS Vulnerability Test
# $Id: ircd.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# IRC Server Banner Detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11156");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IRC Server Banner Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/irc", 6667, 6697, 7697);

  script_tag(name:"summary", value:"This script tries to detect the banner of an IRC server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

ports = get_kb_list( "Services/irc" );
if( ! ports )
  ports = make_list( 6667,  6697, 7697);

host = get_host_name();

foreach port( ports ) {

  if( ! get_port_state( port ) )
    continue;

  soc = open_sock_tcp( port );
  if( ! soc )
    continue;

  # nb: Don't use service_is_unknown() as we want to fetch the version as well...

  final_banner = "";
  host_banner = "";
  nick = NULL;
  blocked = FALSE;

  # nb: Generating a random nickname / login name
  for( i = 0; i < 9; i++ )
    nick += raw_string( 0x41 + ( rand() % 10 ) );

  user = nick;

  req = string( "NICK ", nick, "\r\n",
                "USER ", nick, " ", this_host_name(), " ", host, " :", user, "\r\n" );
  send( socket:soc, data:req );

  while( a = recv_line( socket:soc, length:4096 ) ) {
    n++;
    if( a =~ "^PING." ) {
      a = ereg_replace( pattern:"PING", replace:"PONG", string:a );
      send( socket:soc, data:a );
    } else if( a =~ "^ERROR :Closing Link" ||
               a =~ "^ERROR :Your host is trying to" ||
               a =~ "^ERROR :Trying to reconnect too fast" ) {
      close( soc );
      set_kb_item( name:"ircd/detected", value:TRUE );
      log_message( port:port, data:'Unable to get the version of this service due to the error:\n\n' + a );
      register_service( port:port, proto:"irc", message:"An IRC server seems to be running on this port." );
      blocked = TRUE;
      break;
    } else if( a =~ "^:.* :Your host is .*, running version " ) {
      host_banner = a;
    }
    if( n > 256 ) # nb: Too much data...
      break;
  }

  # nb: Socket was already closed above and the log_message about the service was sent.
  if( blocked )
    continue;

  send( socket:soc, data:string( "VERSION\r\n" ) );
  v = "x";
  while( ( v ) && " 351 " >!< v ) {
    v = recv_line( socket:soc, length:256 );
  }
  send( socket:soc, data:string( "QUIT\r\n" ) );
  close( soc );

  if( ( ! v || v !~ "^:.* 351 " ) && host_banner !~ "^:.* :Your host is .*, running version " )
    continue;

  # Answer looks like:
  # :irc.$hostname 351 $randomchars 2.8/csircd-1.13. irc.$hostname :http://www.codestud.com/ircd
  # :unknown.host 351 $randomchars Unreal3.2.8.1. unknown.host :FhinXeOoE [*=2309]
  # :irc.$hostname 351 $randomchars hybrid-1:8.2.21+dfsg.1-1(20161127_7917). irc.$hostname :TSow
  if( v && v =~ "^:.* 351 " ) {
    final_banner = chomp( v );
  # nb: Some servers are not answering to the VERSION request so try to catch the
  #  "Your host is...running version" banner instead. e.g.:
  # :irc.$hostname $randomnum $randomchars :Your host is $hostname[0.0.0.0/6667], running version hybrid-1:8.2.21+dfsg.1-1
  # :unknown.host $randomnum $randomchars :Your host is unknown.host, running version Unreal3.2.8.1
  # :$hostname $randomnum $randomchars ::Your host is $hostname, running version u2.10.H.10.250
  } else if( host_banner && host_banner =~ "^:.* :Your host is .*, running version " ) {
    final_banner = chomp( host_banner );
  } else {
    continue;
  }

  register_service( port:port, proto:"irc", message:"An IRC server seems to be running on this port." );

  set_kb_item( name:"irc/banner/" + port, value:final_banner );
  set_kb_item( name:"ircd/detected", value:TRUE );
  set_kb_item( name:"ircd/banner", value:TRUE );

  log_message( port:port, data:'The IRC server banner is:\n\n' + final_banner );
  continue;
}