###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rpc_portmap_tcp.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# RPC portmapper (TCP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108090");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RPC portmapper (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("RPC");
  script_dependencies("secpod_rpc_portmap_udp.nasl");
  script_require_ports(111, 121, 530, 593);

  script_tag(name:"summary", value:"This script performs detection of RPC portmapper on TCP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("byte_func.inc");

RPC_PROG = 100000;
ports = make_list( 111, 121, 530, 593 );

foreach p( ports ) {

  port = FALSE;

  if( ! get_tcp_port_state( p ) ) continue;

  port = get_rpc_port( program:RPC_PROG, protocol:IPPROTO_TCP, portmap:p );
  if( ! port ) continue;

  replace_kb_item( name:"rpc/portmap", value:p );
  set_kb_item( name:"rpc/portmap/tcp/detected", value:TRUE );
  set_kb_item( name:"rpc/portmap/tcp_or_udp/detected", value:TRUE );
  register_service( port:p, proto:"rpc-portmap" );
  log_message( port:p, data:"RPC portmapper is running on this port." );
}

exit( 0 );