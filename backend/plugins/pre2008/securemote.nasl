###############################################################################
# OpenVAS Vulnerability Test
#
# Checkpoint SecureRemote detection
#
# Authors:
# Yoav Goldberg <yoavg@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10617");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Checkpoint SecureRemote detection");
  script_category(ACT_GATHER_INFO);
  script_family("Firewalls");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("find_service.nasl");
  script_require_ports(264);

  script_xref(name:"URL", value:"http://www.securiteam.com/securitynews/CheckPoint_FW1_SecureRemote_DoS.html");

  script_tag(name:"solution", value:"Restrict access to this port from untrusted networks.");

  script_tag(name:"summary", value:"The remote host seems to be a Checkpoint FW-1 running SecureRemote.");

  script_tag(name:"impact", value:"Letting attackers know that you are running FW-1 may enable them to
  focus their attack or will make them change their attack strategy.

  You should not let this information leak out. Furthermore, an attacker can perform
  a denial of service attack on the machine.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = 264;
if( ! get_port_state( port ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

SecureRemote = FALSE;
buffer1 = raw_string( 0x41, 0x00, 0x00, 0x00 );
buffer2 = raw_string( 0x02, 0x59, 0x05, 0x21 );

send( socket:soc, data:buffer1 );
send( socket:soc, data:buffer2 );
response = recv( socket:soc, length:5 );
close( soc );

if( response == buffer1 )
  SecureRemote = TRUE;

if( SecureRemote ) {
  set_kb_item( name:"Host/firewall", value:"Checkpoint Firewall-1" );
  security_message( port:port );
  exit( 0 );
}

exit( 99 );