###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solarwinds_log_event_manager_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# SolarWinds Log & Event Manager Web Interface Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105448");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-12 14:10:31 +0100 (Thu, 12 Nov 2015)");
  script_name("SolarWinds Log & Event Manager Web Interface Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

include("host_details.inc");

port = get_http_port( default:8080 );

buf = http_get_cache( item:"/", port:port );

if( "<title>SolarWinds Log &amp; Event Manager</title>" >!< buf ) exit( 0 );

set_kb_item( name:"solarwinds_lem/installed", value:TRUE );

url = '/lem/assets/config/version.txt';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( buf !~ '^[0-9.]+$' ) exit( 0 );

set_kb_item( name:"solarwinds_lem/version/http", value:buf );

report = 'Detected SolarWinds Log & Event Manager Web Interface\n' +
         'Location: /\n' +
         'Version: ' + buf + '\n' +
         'CPE: cpe:/a:solarwinds:log_and_event_manager:' + buf;

log_message( port:port, data:report );
exit( 0 );

