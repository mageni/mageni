###############################################################################
# OpenVAS Vulnerability Test
#
# NetAsq identification
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14378");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetAsq identification");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Firewalls");
  script_dependencies("find_service.nasl");
  script_require_ports(1300);

  script_xref(name:"URL", value:"http://www.netasq.com");

  script_tag(name:"solution", value:"Do not allow any connection on the
  firewall itself, except from trusted network.");

  script_tag(name:"summary", value:"It's very likely that this remote host is a NetAsq IPS-Firewalls
  with port TCP/1300 open to allow Firewall Manager tool to remotely configure it.

  Letting attackers know that you are using a NetAsq will help them to focus their attack or will
  make them change their strategy.

  You should not let them know such information.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

port = 1300;
if( ! get_port_state( port ) )
  exit( 0 );

soc = open_sock_tcp( port);
if( ! soc )
  exit( 0 );

req = string( "VT-TEST\r\n" );
send( socket:soc, data:req );
r = recv( socket:soc, length:512 );

if( ereg( pattern:"^200 code=[0-9]+ msg=.*", string:r ) ) {
  req = string( "QUIT\r\n" );
  send(socket:soc, data:req);
  r = recv( socket:soc, length:512 );
  if( ereg( pattern:"^103 code=[0-9]+ msg=.*\.\.\.", string:r ) ) {
    log_message( port:port );
  }
}

close( soc );
exit( 0 );