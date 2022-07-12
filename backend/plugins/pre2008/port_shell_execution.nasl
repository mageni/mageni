###############################################################################
# OpenVAS Vulnerability Test
# $Id: port_shell_execution.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# Shell Command Execution Vulnerability
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecurITeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10879");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Shell Command Execution Vulnerability");
  script_category(ACT_DESTRUCTIVE_ATTACK); # Potentially destructive
  script_copyright("This script is Copyright (C) 2001 SecurITeam");
  script_family("Gain a shell remotely");
  script_dependencies("secpod_open_tcp_ports.nasl");
  script_mandatory_keys("TCP/PORTS");

  script_tag(name:"solution", value:"Make sure all meta characters are filtered out, or close the port
  for access from untrusted networks");

  script_tag(name:"summary", value:"The remote port seems to be running some form of shell script,
  with some provided user input. The input is not stripped for such meta
  characters as `' etc. This would allow a remote attacker to execute arbitrary code.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");

function test_port( port, command ) {

  soc = open_sock_tcp( port );
  if( soc ) {
    data = string( "`", command, "` #\r\n" );
    send( socket:soc, data:data );

    buf = recv( socket:soc, length:65535, min:1 );
    looking_for = string( "uid=" );

    close( soc );

    if( looking_for >< buf ) {
      report  = "Sent request:      " + data + '\n';
      report += "Received response: " + buf;
      security_message( port:port );
      exit( 0 );
    }
  }
}

function test_for_backtick( port ) {

  soc = open_sock_tcp( port );
  if( soc ) {

    data = string( "`\r\n" );
    send( socket:soc, data:data );

    buf = recv( socket:soc, length:65535, min:1 );

    looking_for = string( "sh: unexpected EOF while looking for " );
    looking_for_2 = raw_string( 0x60, 0x60, 0x27 );
    looking_for = string( looking_for, looking_for_2 );

    close( soc );

    if( looking_for >< buf ) {
      report  = "Sent request:      " + data + '\n';
      report += "Received response: " + buf;
      security_message( port:port );
      exit( 0 );
    }
  }
}

port = get_all_tcp_ports();

test_for_backtick( port:port );
test_port( port:port, command:"/bin/id" );
test_port( port:port, command:"/usr/bin/id" );

exit( 99 );