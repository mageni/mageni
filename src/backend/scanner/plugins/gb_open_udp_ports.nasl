###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_udp_ports.nasl 13298 2019-01-25 15:06:49Z cfischer $
#
# Checks for open UDP ports
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.103978");
  script_version("$Revision: 13298 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-25 16:06:49 +0100 (Fri, 25 Jan 2019) $");
  script_tag(name:"creation_date", value:"2012-02-08 21:19:00 +0200 (Wed, 08 Feb 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Checks for open UDP ports");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("global_settings.nasl");

  script_add_preference(name:"Silent", type:"checkbox", value:"yes");

  script_tag(name:"summary", value:"Collects all open UDP ports identified so far.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

opened_udp_ports = ""; # nb: To make openvas-nasl-lint happy...

silent = script_get_preference( "Silent" );
if( silent == 'yes' )
  be_silent = TRUE;

udp_ports = get_kb_list( "Ports/udp/*" );

if( ! udp_ports || ! is_array( udp_ports ) ) {
  if( ! be_silent )
    log_message( port:0, data:"Open UDP ports: [None found]", proto:"udp" );
  exit( 0 );
}

set_unknown = get_kb_item( "global_settings/non-default_udp_service_discovery" );

# Sort to not report changes on delta reports if just the order is different
keys = sort( keys( udp_ports ) );

foreach port( keys ) {

  _port = eregmatch( string:port, pattern:"Ports/udp/([0-9]+)" );
  if( ! _port && ! get_udp_port_state( _port[1] ) )
    continue;

  set_kb_item( name:"UDP/PORTS", value:_port[1] );
  if( set_unknown )
    set_kb_item( name:"Services/udp/unknown", value:_port[1] );
  opened_udp_ports += _port[1] + ", ";
}

if( strlen( opened_udp_ports ) ) {

  opened_udp_ports = ereg_replace( string:chomp( opened_udp_ports ), pattern:",$", replace:"" );
  opened_udp_ports_kb = str_replace( string:opened_udp_ports, find:" ", replace:"" );
  set_kb_item( name:"Ports/open/udp", value:opened_udp_ports_kb );
  register_host_detail( name:"udp_ports", value:opened_udp_ports_kb, desc:"Checks for open UDP ports" );

  if( be_silent )
    exit( 0 );

  log_message( port:0, data:"Open UDP ports: " + opened_udp_ports, proto:"udp" );
} else {
  if( ! be_silent )
    log_message( port:0, data:"Open UDP ports: [None found]", proto:"udp" );
}

exit( 0 );