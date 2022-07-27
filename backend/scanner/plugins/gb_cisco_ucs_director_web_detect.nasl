###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_director_web_detect.nasl 11020 2018-08-17 07:35:00Z cfischer $
#
# Cisco UCS Director Web Interface Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105576");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11020 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:35:00 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-03-17 16:05:49 +0100 (Thu, 17 Mar 2016)");
  script_name("Cisco UCS Director Web Interface Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to detect the Cisco UCS Director Web Interface from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:443 );

url = '/app/ui/login.jsp';
buf = http_get_cache( item:url, port:port );

if( "<title>Login</title>" >!< buf || ">Cisco UCS Director<" >!< buf || "Cisco Systems, Inc." >!< buf ) exit( 0 );

set_kb_item( name:"cisco_ucs_director/webgui", value:TRUE );
set_kb_item( name:"cisco_ucs_director/webgui/port", value:port );

log_message( port:port, data:'The Cisco UCS Director Web Interface is running at this port' );
exit( 0 );

