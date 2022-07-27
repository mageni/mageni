###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_open_tcp_ports.nasl 13719 2019-02-18 07:37:06Z asteins $
#
# Checks for open TCP ports
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900239");
  script_version("$Revision: 13719 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 08:37:06 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-04-16 11:02:50 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Checks for open TCP ports");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("dont_scan_printers.nasl", "dont_print_on_printers.nasl");

  script_add_preference(name:"Silent", type:"checkbox", value:"yes");

  script_tag(name:"summary", value:"Collects all open TCP ports identified so far.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

opened_tcp_ports = ""; # nb: To make openvas-nasl-lint happy...

silent = script_get_preference( "Silent" );
if( silent == 'yes' )
  be_silent = TRUE;

tcp_ports = get_kb_list( "Ports/tcp/*" );

if( ! tcp_ports || ! is_array( tcp_ports ) ) {
  if( ! be_silent )
    log_message( port:0, data:"Open TCP ports: [None found]" );
  exit( 0 );
}

# Sort to not report changes on delta reports if just the order is different
keys = sort( keys( tcp_ports ) );

foreach port( keys ) {

  _port = eregmatch( string:port, pattern:"Ports/tcp/([0-9]+)" );
  if( ! _port && ! get_port_state( _port[1] ) )
    continue;

  # Includes e.g. PJL ports which are printing everything
  # sent to them so don't include this ports here
  if( ! is_fragile_port( port:_port[1] ) )
    set_kb_item( name:"TCP/PORTS", value:_port[1] );

  opened_tcp_ports += _port[1] + ", ";
}

if( strlen( opened_tcp_ports ) ) {

  opened_tcp_ports = ereg_replace( string:chomp( opened_tcp_ports ), pattern:",$", replace:"" );
  opened_tcp_ports_kb = str_replace( string:opened_tcp_ports, find:" ", replace:"" );
  set_kb_item( name:"Ports/open/tcp", value:opened_tcp_ports_kb );
  register_host_detail( name:"ports", value:opened_tcp_ports_kb, desc:"Check Open TCP Ports" );
  register_host_detail( name:"tcp_ports", value:opened_tcp_ports_kb, desc:"Check Open TCP Ports" );

  if( be_silent )
    exit( 0 );

  log_message( port:0, data:"Open TCP ports: " + opened_tcp_ports );
} else {
  if( ! be_silent )
    log_message( port:0, data:"Open TCP ports: [None found]" );
}

exit( 0 );
