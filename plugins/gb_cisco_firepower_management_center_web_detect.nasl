###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firepower_management_center_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco FirePOWER Management Center Web Interface Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105521");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-19 17:03:19 +0100 (Tue, 19 Jan 2016)");
  script_name("Cisco FirePOWER Management Center Web Interface Detection");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Cisco FirePOWER Management Center.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

source = "http";

port = get_http_port( default:443 );

url = '/help_files/g_Introduction_to_the_Cisco_Firepower_System.html';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Introduction to the Cisco Firepower System" >!< buf ) exit( 0 );

url = '/login.cgi';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Login</title>" >!< buf || "Cisco" >!< buf ) exit( 0 );

set_kb_item( name:'cisco_fire_linux_os/installed', value:TRUE );

version = eregmatch( pattern:'\\?v=([0-9.]+)-([0-9]+)', string:buf );

if( ! isnull( version[1] ) ) set_kb_item( name:"cisco/firepower/" + source + "/version", value:version[1]);
if( ! isnull( version[2] ) ) set_kb_item( name:"cisco/firepower/" + source + "/build", value:version[2]);

report = 'The Cisco FirePOWER Management Center Web Interface is running at this port.';
log_message( port:port, data:report );
exit( 0 );

