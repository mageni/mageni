###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sophos_xg_detect_userportal.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Sophos XG Firewall Userportal Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105626");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-27 12:37:42 +0200 (Wed, 27 Apr 2016)");
  script_name("Sophos XG Firewall Userportal Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

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

url = '/userportal/webpages/myaccount/login.jsp';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Server: xxxx" >!< buf || buf !~ "HTTP/1\.. 200" || "<title>Sophos</title>" >!< buf || 'Cyberoam.setContextPath("/userportal");' >!< buf ) exit( 0 );

url = '/javascript/lang/English/common.js';
req = http_get( item:url, port:port );
buf1 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf1 !~ 'Sophos [^ ]*Firewall' && "Cyberroam" >!< buf1) exit( 0 );

set_kb_item( name:"sophos/xg/installed", value:TRUE );

vers = 'unknown';
cpe = 'cpe:/a:sophos:xg';

version = eregmatch( pattern:'ver=([0-9]+\\.[^"\' ]+)', string:buf ); # example: ver=15.01.0.418. 418 seems to be the "build".
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:'/userportal', port:port );

log_message( data: build_detection_report( app:"Sophos XG Firewall Userportal",
                                           version:vers,
                                           install:"/userportal",
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port );

exit(0);

