###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owa_detect.nasl 5992 2017-04-20 14:42:07Z cfi $
#
# Outlook Web App Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105150");
  script_version("$Revision: 5992 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-20 16:42:07 +0200 (Thu, 20 Apr 2017) $");
  script_tag(name:"creation_date", value:"2014-12-22 14:13:35 +0100 (Mon, 22 Dec 2014)");
  script_name("Outlook Web App Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection
  request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:443 );
if( ! can_host_asp( port:port ) ) exit( 0 );

url = '/owa/auth/logon.aspx';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Microsoft Corporation.  All rights reserved" >< buf &&  ( "<title>Outlook Web App" >< buf || "X-OWA-Version:" >< buf  ) ) {

  version = eregmatch( pattern:'X-OWA-Version: ([0-9.]+)', string:buf );

  if( isnull( version[1] ) )
    version = eregmatch( pattern:'/owa/([0-9.]+)/themes/', string:buf );

  if( isnull( version[1] ) )
    version = eregmatch( pattern:'/owa/auth/([0-9.]+)/themes/', string:buf );

  if( ! isnull( version[1] ) ) vers = version[1];

  cpe = 'cpe:/a:microsoft:outlook_web_app';
  if( vers ) cpe += ':' + vers;

  set_kb_item( name:"ms/owa/installed", value:TRUE );

  register_product( cpe:cpe, location:url, port:port );

  log_message( data: build_detection_report( app:"Outlook Web App",
                                             version:vers,
                                             install:url,
                                             cpe:cpe,
                                             concluded: version[0]),
               port:port );

  exit( 0 );

}

exit( 0 );
