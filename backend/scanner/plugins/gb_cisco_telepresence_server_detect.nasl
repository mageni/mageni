###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telepresence_server_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco TelePresence Server Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105284");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-03 11:50:04 +0200 (Wed, 03 Jun 2015)");
  script_name("Cisco TelePresence Server Detection");

  script_tag(name:"summary", value:"The script sends a connection
request to the server and attempts to extract the version number
from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = '/system.xml';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<model>telepresence server" >!< tolower( buf ) ) exit( 0 );

cpe = 'cpe:/a:cisco:telepresence_server_software';
vers = 'unknown';
model = 'unknown';
build = 'unknown';

version = eregmatch( string: buf, pattern: "<softwareVersion>([^<]+)</softwareVersion>", icase:TRUE );
if ( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:"cisco_telepresence_server/version",value:vers ); # e.g. 3.0(2.48)
}

_build = eregmatch( string: buf, pattern: "<buildVersion>([^<]+)</buildVersion>", icase:TRUE );
if ( ! isnull( _build[1] ) )
{
  build = _build[1];
  set_kb_item( name:"cisco_telepresence_server/build",value:build );
}

_model = eregmatch( string: buf, pattern: "<model>Telepresence Server (on )?([^<]+)</model>", icase:TRUE );
if ( ! isnull( _model[2] ) )
{
  model = _model[2];
  if( "Virtual Machine" >< model ) model = "VM";
  set_kb_item( name:"cisco_telepresence_server/model",value:model );
}

set_kb_item( name:"cisco_telepresence_server/installed",value:TRUE );

register_product( cpe:cpe, location:"/", port:port );

log_message( data: build_detection_report( app:"Cisco Telepresence Server (" + model +")",
                                           version:vers,
                                           install:"/",
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port );

exit(0);

