###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_router_routeros_webui_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# MikroTik RouterOS Detection (Web UI)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113071");
  script_version("$Revision: 11885 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-14 13:25:48 +0100 (Thu, 14 Dec 2017)");
  script_name("MikroTik RouterOS Detection (Web UI)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 10000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of MikroTik RouterOS via Web UI.

  The script sends a connection request to the server and attempts to
  detect the presence of MikroTik Router.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default: 10000 );
res = http_get_cache( port: port, item: "/" );

# <div class="top">mikrotik routeros 6.19 configuration page</div>
# <h1>RouterOS v6.34.6</h1>
if( ( ">RouterOS router configuration page<" >< res && "mikrotik<" >< res && ">Login<" >< res ) ||
    ( ">mikrotik routeros" >< res && "configuration page</div>" >< res ) ) {

  version = "unknown";
  install = port + "/tcp";
  set_kb_item( name:"mikrotik/detected", value:TRUE );
  set_kb_item( name:"mikrotik/www/detected", value:TRUE );

  vers = eregmatch( pattern:">RouterOS v([A-Za-z0-9.]+)<", string:res );
  if( ! vers[1] ) vers = eregmatch( pattern:">mikrotik routeros ([A-Za-z0-9.]+) configuration page<", string:res );
  if( vers[1] ) version = vers[1];

  if( version != "unknown" ) {
    set_kb_item( name: "mikrotik/webui/" + port + "/concluded", value: vers[0] );
  }

  set_kb_item( name: "mikrotik/webui/port", value: port );
  set_kb_item( name: "mikrotik/webui/" + port + "/version", value: version );
}

exit( 0 );
