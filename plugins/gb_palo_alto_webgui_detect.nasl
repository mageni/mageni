###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_palo_alto_webgui_detect.nasl 8720 2018-02-08 13:20:07Z cfischer $
#
# Palo Alto Device Detection (Web UI)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105261");
  script_version("$Revision: 8720 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-08 14:20:07 +0100 (Thu, 08 Feb 2018) $");
  script_tag(name:"creation_date", value:"2015-04-22 13:08:50 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Palo Alto Device Detection (Web UI)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request
  to the server and attempts to detect the Web UI for Palo Alto devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:443 );
banner = get_http_banner( port:port );
res = http_get_cache( item:"/php/login.php", port:port );

# Newer Devices / Firmware (e.g. PA-220) don't have a server banner at all
if( "Server: PanWeb Server/" >< banner ||
    ( "Pan.base.cookie.set" >< res && "BEGIN PAN_FORM_CONTENT" >< res ) ||
    ( "'js/Pan.js'></script>" >< res && ( "/login/images/logo-pan-" >< res || "/images/login-page.gif" >< res ) ) ) {

  # Currently no FW Version / Product name exposed unauthenticated
  fw_version = "unknown";
  model      = "unknown";

  set_kb_item( name:"palo_alto/detected", value:TRUE );
  set_kb_item( name:"palo_alto/webui/detected", value:TRUE );
  set_kb_item( name:"palo_alto/webui/port", value:port );
  set_kb_item( name:"palo_alto/webui/" + port + "/fw_version", value:fw_version );
  set_kb_item( name:"palo_alto/webui/" + port + "/model", value:model );
  set_kb_item( name:"palo_alto/webui/" + port + "/concluded", value:"HTTP(s) Login Page" );
}

exit( 0 );
