###############################################################################
# OpenVAS Vulnerability Test
#
# Check for Writesrv Service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11222");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Check for Writesrv Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Useless services");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 2401);

  script_tag(name:"summary", value:"writesrv is running on this port, it is used to send messages
  to users.");

  script_tag(name:"solution", value:"Disable this service if you don't use it.");

  script_tag(name:"impact", value:"This service gives potential attackers information about who
  is connected and who isn't, easing social engineering attacks for example.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");

port = get_unknown_port(default:2401);

s = open_sock_tcp(port);
if(!s)
  exit(0);

m1 = "VT-TEST" + raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
l0 = raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
m2 = "root" + raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

m = m1 + l0;
for(i=2; i < 32; i++)
  m = m + l0;

m = m + m2;
for(i=2; i < 32; i++)
  m = m + l0;

m = m + raw_string(0x2e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, l0);
send(socket:s, data:m);
r = recv( socket:s, length:1536 );
close(s);

len = strlen( r );
if( len < 512 )
  exit( 0 ); # Can 'magic read' break this?

# It seems that the answer is split into 512-bytes blocks padded
# with nul bytes:
# <digit> <space> <digit> <enough bytes...>
# Then, if the user is logged:
# <ttyname> <nul bytes...>
# And maybe another block
# <tty2name> <nul bytes...>

for( i = 16; i < 512; i++ ) {
  if( ord( r[i] ) != 0 )
    exit( 0 );
}

security_message( port:port );
exit( 0 );