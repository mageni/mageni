###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adcon_A840_telemetry_gateway_http_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Adcon A840 Telemetry Gateway Detection (HTTP)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105489");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-17 16:12:43 +0100 (Thu, 17 Dec 2015)");
  script_name("Adcon A840 Telemetry Gateway Detection (HTTP)");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

buf =  http_get_cache( item:"/", port:port );
if( ! buf || "Welcome to the A840 Telemetry Gateway" >!< buf ) exit( 0 );

set_kb_item( name:"tg_A840/installed", value:TRUE );
set_kb_item( name:"tg_A840/http/port", value:port );

version = eregmatch( pattern:'>Release ([0-9.]+[^,]+),', string:buf );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:'tg_A840/http/version', value:vers );
}

report = 'Detected Adcon Telemetry Gateway A840.\n';
if( vers ) report += 'Version: ' + vers + '\n';

log_message( port:port, data:report );

exit(0);
