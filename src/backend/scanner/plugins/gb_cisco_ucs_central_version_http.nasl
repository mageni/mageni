###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_central_version_http.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco UCS Central Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105572");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-17 13:41:17 +0100 (Thu, 17 Mar 2016)");
  script_name("Cisco UCS Central Detectioni (HTTP)");

  script_tag(name:"summary", value:"This Script performs HTTP based detection of Cisco UCS Central");

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

source = "http";

port = get_http_port( default:443 );

url = '/ui/faces/Login.xhtml';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>UCS Central</title>" >!< buf || "/cisco/" >!< buf || "Cisco UCS Central" >!< buf ) exit( 0 );

cpe = 'cpe:/a:cisco:ucs_central_software';
set_kb_item( name:"cisco_ucs_central/installed", value:TRUE );
set_kb_item( name:"cisco_ucs_central/" + source + "/port", value:port );

vers = 'unknown';

version = eregmatch( pattern:'/ui/resources/static/([0-9.]+[^/]+)/cisco/', string:buf );
if( ! isnull( version[1] ) )
{
  vers = version[1]; # for example 1.4_1a, via show version: 1.4(1a)
  vers = str_replace( string:vers, find:"_", replace:"(" );
  vers += ')';
  cpe += ':' + vers;
  set_kb_item( name:"cisco_ucs_central/" + source + "/version", value:vers );
}

report = build_detection_report( app:"Cisco UCS Central", version:vers, install:"HTTP(s)", cpe:cpe, concluded:version[0] );
log_message( port:port, data:report );

exit( 0 );


