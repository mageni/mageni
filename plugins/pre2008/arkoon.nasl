###############################################################################
# OpenVAS Vulnerability Test
# $Id: arkoon.nasl 4831 2016-12-21 12:32:45Z cfi $
#
# Arkoon identification
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14377");
  script_version("2019-04-11T11:45:42+0000");
  script_tag(name:"last_modification", value:"2019-04-11 11:45:42 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Arkoon identification");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Firewalls");
  script_dependencies("find_service.nasl");
  script_require_ports(822, 1750, 1751);

  script_xref(name:"URL", value:"http://www.arkoon.net");

  script_tag(name:"solution", value:"Do not allow any connection on the firewall itself,
  except for the firewall protocol, and allow that for trusted sources only.

  If you have a router which performs packet filtering, then add ACL that disallows the
  connection to these ports for unauthorized systems.");

  script_tag(name:"summary", value:"The remote host has the three TCP ports 822, 1750, 1751
  open.

  It's very likely that this host is an Arkoon security dedicated appliance with ports:

  TCP/822  dedicated to ssh service

  TCP/1750 dedicated to Arkoon Manager

  TCP/1751 dedicated to Arkoon Monitoring");

  script_tag(name:"impact", value:"Letting attackers know that you are using an Arkoon
  appliance will help them to focus their attack or will make them change their strategy.

  You should not let them know such information.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if( ( get_port_state( 822 ) ) &&
    ( get_port_state( 1750 ) ) &&
    ( get_port_state( 1751 ) ) ) {

  soc1 = open_sock_tcp( 822 );
  if( ! soc1 ) exit( 0 );
  banner = recv_line( socket:soc1, length:1024 );
  close( soc1 );
  #SSH-1.5-SSF
  if( ! ( egrep( pattern:"SSH-[0-9.]+-SSF", string:banner ) ) ) exit( 0 );

  soc2 = open_sock_tcp( 1750 );
  if( ! soc2 ) exit( 0 );
  close( soc2 );

  soc3 = open_sock_tcp( 1751 );
  if( ! soc3 ) exit( 0 );
  close( soc3 );

  # post the warning on every port
  log_message( port:0 );
}

exit( 0 );