###############################################################################
# OpenVAS Vulnerability Test
# $Id: nortel_baystack_default_pass.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Nortel Baystack switch password test
#
# Authors:
# Douglas Minderhout <dminderhout@layer3com.com>
# Based upon a script by Rui Bernardino <rbernardino@oni.pt>
#
# Copyright:
# Copyright (C) 2003 Douglas Minderhout
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
  script_oid("1.3.6.1.4.1.25623.1.0.11327");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Nortel Baystack switch password test");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Douglas Minderhout");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/nortel_networks/baystack/detected");

  script_tag(name:"solution", value:"Telnet to this switch and set passwords under 'Console/Comm Port Configuration' for both
  read only and read write. Then, set the parameter 'Console Switch Password' or 'Console Stack Password'
  to 'Required for TELNET' or 'Required for Both'.");

  script_tag(name:"summary", value:"The remote switch has a weak password.");

  script_tag(name:"impact", value:"This means that anyone who has (downloaded) a user manual can telnet to it and gain
  administrative access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");

function myrecv( socket, pattern ) {

  while( 1 ) {
    r = recv_line( socket:soc, length:1024 );
    if( strlen( r ) == 0 ) return( 0 );
    if( ereg( pattern:pattern, string:r ) ) return( r );
  }
}

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );
if( ! banner || ( "Ctrl-Y" >!< banner && "P Configuration" >!< banner ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

buf = telnet_negotiate( socket:soc );

# If we catch one of these, it's something else
if( "NetLogin:" >< buf || "Login:" >< buf ) {
  close( soc );
  exit( 0 );
}

# If we get Ctrl-Y in the response we're in business
if( "Ctrl-Y" >< buf ) {

  # Here we send it the Ctrl-y in HEX
  test = raw_string( 0x19, 0xF0 );
  send( socket:soc, data:test );
  resp = recv( socket:soc, length:1024 );

  if( "P Configuration" >< resp ) {
    # No password has been set
    report = string( "There is no password assigned to the remote Baystack switch." );
    close( soc );
    security_message( port:port, data:report );
    exit( 0 );
  } else {
    if( "asswor" >< resp ) {
      # A password has been set, now we try some defaults
      test = string( "secure\r" );
      send( socket:soc, data:test );
      resp = recv( socket:soc, length:1024 );
      if( "P Configuration" >< resp ) {
        report = string( "The default password 'secure' is assigned to the remote Baystack switch." );
        close( soc );
        security_message( port:port, data:report );
        exit( 0 );
      } else {
        if( "asswor" >< resp ) {
          # "secure' didn't work, let's try "user"
          test = string( "user\r" );
          send( socket:soc, data:test );
          resp = recv( socket:soc, length:1024 );
          if( "P Configuration" >< resp ) {
            report = string ("The default password 'user' is assigned to the remote Baystack switch.");
            close( soc );
            security_message( port:port, data:report );
            exit( 0 );
          }
        }
      }
    }
  }
# The older switches do not do the Ctrl-Y thing, they just let you in
} else {
  if ("P Configuration" >< buf) {
    report = string ("There is no password assigned to the remote Baystack switch. This switch is most likely using a very old version of software. It would be best to contact Nortel for an upgrade.");
    close (soc);
    security_message(port:port, data:report);
    exit( 0 );
  }
}

close( soc );
exit( 99 );