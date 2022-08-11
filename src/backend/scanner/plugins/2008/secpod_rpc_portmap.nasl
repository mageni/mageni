###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rpc_portmap.nasl 5487 2017-03-04 19:00:02Z cfi $
#
# RPC portmapper (UDP)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.312706");
  script_version("$Revision: 5487 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-04 20:00:02 +0100 (Sat, 04 Mar 2017) $");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RPC portmapper (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("RPC");
  script_dependencies("secpod_rpc_portmap_tcp.nasl");
  script_require_udp_ports(111, 121, 530, 593);

  script_tag(name:"summary", value:"This script performs detection of RPC portmapper on UDP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");

RPC_PROG = 100000;
ports = make_list( 111, 121, 530, 593 );

foreach p( ports ) {

  port = FALSE;

  if( get_udp_port_state( p ) ) {
    port = get_rpc_port( program:RPC_PROG, protocol:IPPROTO_UDP, portmap:p );
    if( port ) {
      replace_kb_item( name:"rpc/portmap", value:p );
      register_service( port:p, proto:"rpc-portmap", ipproto:"udp" );
      log_message( port:p, data:"RPC portmapper is running on this port", proto:"udp" );
    }
  }
}

exit( 0 );
