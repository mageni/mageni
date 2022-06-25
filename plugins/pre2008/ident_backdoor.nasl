###############################################################################
# OpenVAS Vulnerability Test
# $Id: ident_backdoor.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# IRC bot ident server detection
#
# Authors:
# Brian Smith-Sweeney (brian@smithsweeney.com)
# http://www.smithsweeney.com
#
# Copyright:
# Copyright (C) 2004 Brian Smith-Sweeney
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

# Created: 9/22/04
# Last Updated: 11/25/04
#
# Revision History:
# v1.1 - first released version
# v1.2
#  * Registered security_message on "port" variable instead of static 113
#  * Made socket timeouts and pause between socket connections variable
#  * Changed default socket timeout to 5 seconds to deal with bots that
#    refuse connections in quick succession (NOTE: 10 seconds is the most
#    accurate I've seen, but it makes the test *much* slower)

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14841");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IRC bot ident server detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Brian Smith-Sweeney");
  script_family("Malware");
  script_require_ports("Services/auth", 113);
  script_dependencies("find_service1.nasl");

  script_tag(name:"solution", value:"re-install the remote system");

  script_tag(name:"summary", value:"This host seems to be running an ident server, but the ident server responds
  to an empty query with a random userid. This behavior may be indicative of an
  irc bot, worm, and/or virus infection. It is very likely this system has
  been compromised.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

# End user-defined variables; you should not have to touch anything below this
soc_out =   3; # Socket connect timeout; increase this for slow ident bots
soc_sleep = 5; # Time to wait between socket connections; increase this for bots
               # that don't respond to multiple requests in quick succession
r = '\r\n';    # Data to send to the auth server at initial connect

port = get_kb_item( "Services/auth" );
if( ! port ) port = 113;
if( ! get_port_state( port ) ) exit( 0 );

soc1 = open_sock_tcp( port );
if( ! soc1 ) exit(0);

if( send( socket:soc1, data:r ) <= 0 ) exit( 0 );

r1 = recv_line( socket:soc1, length:1024, timeout:soc_out );
ids1 = split( r1, sep:':' );

if( "USERID" >< ids1[1] ) {

  close( soc1 );
  sleep( soc_sleep );

  soc2 = open_sock_tcp( port );
  if( ! soc2 ) exit( 0 );

  send( socket:soc2, data:r );
  r2 = recv_line( socket:soc2, length:1024, timeout:soc_out );
  ids2 = split( r2, sep:':' );
  close( soc2 );

  if( "USERID" >< ids2[1] ) {

    if( ids1[3] == ids2[3] ) exit( 0 );

    security_message( port:port );

    if( service_is_unknown( port:port ) )
      register_service(port: port, proto: 'fake-identd');
      set_kb_item( name:'fake_identd/' + port, value:TRUE );
      exit( 0 );
  }
} else {
  close( soc1 );
}

exit( 99 );