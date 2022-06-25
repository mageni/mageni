###############################################################################
# OpenVAS Vulnerability Test
# $Id: zyxel_pwd.nasl 4904 2017-01-02 12:45:48Z cfi $
#
# Default password router Zyxel
#
# Authors:
# Giovanni Fiaschi <giovaf@sysoft.it>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID.
#
# Copyright:
# Copyright (C) 2001 Giovanni Fiaschi
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
  script_oid("1.3.6.1.4.1.25623.1.0.10714");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3161);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-0571");
  script_name("Default password router Zyxel");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 Giovanni Fiaschi");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports(23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"solution", value:"Telnet to this router and set a password immediately.");

  script_tag(name:"summary", value:"The remote host is a Zyxel router with its default password set.");

  script_tag(name:"impact", value:"An attacker could telnet to it and reconfigure it to lock the owner out and to
  prevent him from using his Internet connection, or create a dial-in user to
  connect directly to the LAN attached to it.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = 23;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

r = recv( socket:soc, length:8192, min:1 );
if( "Password:" >!< r ) exit( 0 );

s = string( "1234\r\n" );
send( socket:soc, data:s );
r = recv( socket:soc, length:8192, min:1 );
close( soc );

if( "ZyXEL" >< r ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );