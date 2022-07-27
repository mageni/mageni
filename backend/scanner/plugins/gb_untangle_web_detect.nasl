###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_untangle_web_detect.nasl 11630 2018-09-26 17:09:08Z cfischer $
#
# Untangle NG Firewall Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105813");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11630 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-26 19:09:08 +0200 (Wed, 26 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-07-18 15:32:04 +0200 (Mon, 18 Jul 2016)");
  script_name("Untangle NG Firewall Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Untangle NG Firewall.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = "/auth/login";
buf = http_get_cache( item:url, port:port );

if( "<title>Untangle Administrator Login</title>" >< buf && "username" >< buf && "password" >< buf )
{
  cpe = 'cpe:/a:untangle:ng-firewall';
  set_kb_item( name:"untangle/installed", value:TRUE );

  register_product( cpe:cpe, location:'/', port:port, service:'www' );
  log_message( port:port, data:'The Untangle NG Firewall Webinterface is running at this port.\nCPE: cpe:/a:untangle:ng-firewall');
}

exit( 0 );