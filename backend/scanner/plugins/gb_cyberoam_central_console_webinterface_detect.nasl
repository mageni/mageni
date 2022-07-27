###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyberoam_central_console_webinterface_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cyberoam Central Console Webinterface Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105622");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-26 11:59:19 +0200 (Tue, 26 Apr 2016)");
  script_name("Cyberoam Central Console Webinterface Detection");

  script_tag(name:"summary", value:"This scripte performs HTTP based detection of the Cyberoam Central Console Webinterface");

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
include("host_details.inc");

port = get_http_port( default:80 );

url = '/CCC/login.html';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

cpe = 'cpe:/a:cyberoam:cyberoam_central_console';

if( "<title>Cyberoam Central Console</title>" >< buf && "/CCC/Controller" >< buf && ">www.cyberoam.com<" >< buf )
{
  register_product( cpe:cpe, location:'/CCC', port:port, service:'www' );
  log_message( port:port, data:'The Cyberoam Central Console Webinterface is running at this port.\nCPE: ' + cpe + '\nLocation: /CCC/');
  exit( 0 );
}

exit( 0 );
