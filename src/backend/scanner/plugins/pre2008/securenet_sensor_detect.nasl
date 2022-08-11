###############################################################################
# OpenVAS Vulnerability Test
# $Id: securenet_sensor_detect.nasl 9228 2018-03-28 06:22:51Z cfischer $
#
# Intrusion.com SecureNet sensor detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.18534");
  script_version("$Revision: 9228 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-28 08:22:51 +0200 (Wed, 28 Mar 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Intrusion.com SecureNet sensor detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host appears to be an Intrusion.com SecureNet sensor on this port.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:443 );
if( ! can_host_php( port:port ) ) exit( 0 );

req = http_get( item:"/main/login.php?action=login", port:port );
res = http_send_recv( data:req, port:port );

if( res =~ "^HTTP/1\.[01] 200" && "<title>WBI Login</title>" >< res ) {
  log_message( port:port );
}

exit( 0 );