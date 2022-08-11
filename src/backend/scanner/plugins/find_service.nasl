###############################################################################
# OpenVAS Vulnerability Test
# $Id: find_service.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Wrapper for calling built-in NVT "find_service" which was previously
# a binary ".nes".
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.10330");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  # nb: Don't change this name as it will affect the script preferences of existing scan configs
  # as well as the predefined scan config which uses a fixed name for the preferences.
  script_name("Services");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Written by Renaud Deraison <deraison@cvs.nessus.org>");
  script_dependencies("dont_scan_printers.nasl", "dont_print_on_printers.nasl", "gb_dont_scan_fragile_device.nasl");

  # Keep these settings in sync with the nasl_builtin_find_service.c
  script_add_preference(name:"Number of connections done in parallel : ", value:"6", type:"entry");
  script_add_preference(name:"Network connection timeout : ", value:"20", type:"entry");
  script_add_preference(name:"Network read/write timeout : ", value:"20", type:"entry");
  script_add_preference(name:"Wrapped service read timeout : ", value:"20", type:"entry");

  script_add_preference(name:"SSL certificate : ", type:"file", value:"");
  script_add_preference(name:"SSL private key : ", type:"file", value:"");
  script_add_preference(name:"PEM password : ", type:"password", value:"");
  script_add_preference(name:"CA file : ", type:"file", value:"");
  script_add_preference(name:"Test SSL based services", type:"radio", value:"All;None");

  script_timeout(4*360);

  script_tag(name:"summary", value:"This routine attempts to guess which service is running on the
  remote ports. For instance, it searches for a web server which could listen on another port than
  80 or 443 and makes this information available for other check routines.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

if( get_kb_item( "Host/dead" ) ) exit( 0 );

# Run the built-in NVT "find_service"
plugin_run_find_service();

if( ! COMMAND_LINE ) {

  # nb: Check for zebos_routing_shell and register it to avoid wrong service detection (dns, sip, yahoo messenger, ...)
  p = 2650;
  if( get_port_state( p ) ) {
    soc = open_sock_tcp( p );
    if( soc ) {
      recv = recv( socket:soc, length:128 );
      close( soc );
      if( "ZebOS" >< recv ) {
        register_service( port:p, proto:"zebos_routing_shell", message:"A ZebOS routing shell seems to be running on this port." );
        log_message( port:p, data:"A ZebOS routing shell seems to be running on this port." );
        exit( 0 );
      }
    }
  }

  # This service will be killed during later service detections so avoid this by checking it in here
  p = 27960;
  if( get_port_state( p ) ) {
    soc = open_sock_tcp( p );
    if( soc ) {
      recv = recv( socket:soc, length:128 );
      close( soc );
      if( egrep( pattern:"Welcome (.*). You have ([0-9]+) seconds to identify.", string:recv ) ) {
        register_service( port:p, proto:"enemyterritory", message:"An Enemy Territory Admin Mod seems to be running on this port." );
        log_message( port:p, data:"An Enemy Territory Admin Mod seems to be running on this port." );
        exit( 0 );
      }
    }
  }
}
