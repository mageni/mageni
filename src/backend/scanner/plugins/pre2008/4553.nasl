###############################################################################
# OpenVAS Vulnerability Test
#
# 4553 Parasite Mothership Detect
#
# Authors:
# Chris Gragsone
#
# Copyright:
# Copyright (C) 2002 Violating
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
  script_oid("1.3.6.1.4.1.25623.1.0.11187");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("4553 Parasite Mothership Detect");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Violating");
  script_family("Malware");
  script_dependencies("find_service.nasl");
  script_require_ports(21227, 21317);

  script_tag(name:"solution", value:"Re-install this host.");

  script_tag(name:"summary", value:"The backdoor '4553' seems to be installed on this host, which indicates
  it has been compromised.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

foreach port( make_list( 21227, 21317 ) ) {

  if( ! get_port_state( port ) )
    continue;

  soc = open_sock_tcp( port );
  if( ! soc )
    continue;

  send( socket:soc, data:"-0x45-" );
  data = recv( socket:soc, length:1024 );

  close( soc );
  if( "0x53" >< data || "<title>UNAUTHORIZED-ACCESS!</title>" >< data ) {
    security_message( port:port );
  }
}

exit( 0 );