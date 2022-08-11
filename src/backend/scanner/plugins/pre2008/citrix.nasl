###############################################################################
# OpenVAS Vulnerability Test
# $Id: citrix.nasl 10105 2018-06-07 06:15:01Z cfischer $
#
# Citrix Published Applications Enumeration (Remote)
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
# Based on Citrix Published Application Scanner version 2.0
# by Ian Vitek, ian.vitek@ixsecurity.com
#
# Copyright:
# Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.11138");
  script_version("$Revision: 10105 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-07 08:15:01 +0200 (Thu, 07 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(5817);
  script_name("Citrix Published Applications Enumeration (Remote)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
  script_family("General");
  script_require_udp_ports(1604);

  script_xref(name:"URL", value:"https://web.archive.org/web/20061225071711/http://sh0dan.org:80/files/hackingcitrix.txt");
  script_xref(name:"URL", value:"http://www.securiteam.com/exploits/5CP0B1F80S.html");

  script_tag(name:"summary", value:"The script attempts to enumerate Citrix published Applications.");

  script_tag(name:"impact", value:"The Citrix server is configured in a way which may allow an
  external attacker to enumerate remote services.");

  script_tag(name:"solution", value:"See the references on how to secure the Citrix installation.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

port = 1604;
if( ! get_udp_port_state( port ) ) exit( 0 );
if( ! soc = open_sock_udp( port ) ) exit( 0 );

trickmaster  = raw_string( 0x20, 0x00, 0x01, 0x30, 0x02, 0xFD, 0xA8, 0xE3 );
trickmaster += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
trickmaster += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
trickmaster += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

send( socket:soc, data:trickmaster );
res = recv( socket:soc, length:1024 );
close( soc );
if( ! res ) exit( 0 );
if( ! soc = open_sock_udp( port ) ) exit( 0 );

get_pa  = raw_string( 0x2A, 0x00, 0x01, 0x32, 0x02, 0xFD );
get_pa += raw_string( 0xa8, 0xe3, 0x00, 0x00, 0x00, 0x00 );
get_pa += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
get_pa += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
get_pa += raw_string( 0x00, 0x00, 0x00, 0x00, 0x21, 0x00 );
get_pa += raw_string( 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 );
get_pa += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

send( socket:soc, data:get_pa );
res = recv( socket:soc, length:1024 );
close( soc );
if( ! res ) exit( 0 );

if( res =~ '\x02\x00\x06\x44' ) {
  security_message( port:port, proto:"udp" );
  exit( 0 );
}

exit( 99 );