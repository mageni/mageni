###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_tinyproxy_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Tinyproxy Server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111080");
  script_version("$Revision: 10894 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-02-01 11:00:00 +0100 (Mon, 01 Feb 2016)");
  script_name("Tinyproxy Server Detection");

  script_tag(name:"summary", value:"Detects the installed version of Tinyproxy.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "proxy_use.nasl");
  script_require_ports("Services/http_proxy", 3128, 8888, "Services/www", 8080);

  script_xref(name:"URL", value:"https://tinyproxy.github.io/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_kb_item( "Services/http_proxy" );

if( ! port ) port = 8888;
if( ! get_port_state( port ) ) port = 3128;
if( ! get_port_state( port ) ) port = 8080;
if( ! get_port_state( port ) ) exit( 0 );

req = http_get( item:"http://www.$$$$$", port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( data = egrep( pattern:"^Server: tinyproxy", string:res, icase: TRUE ) ) {

  version = "unknown";

  ver = eregmatch( pattern:"^Server: tinyproxy/([0-9a-zA-Z.]+)", string:data, icase: TRUE );

  if( ver[1] ) version = ver[1];

  set_kb_item( name:"www/" + port + "/tinyproxy", value:version );
  set_kb_item( name:"tinyproxy/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+.[a-zA-Z0-9]+)", base:"cpe:/a:banu:tinyproxy:" );
  if( isnull( cpe ) )
     cpe = "cpe:/a:banu:tinyproxy";

  register_product( cpe:cpe, location:port + '/tcp', port:port );

  log_message( data: build_detection_report( app:"Tinyproxy Server",
                                             version:version,
                                             install:port + '/tcp',
                                             cpe:cpe,
                                             concluded: ver[0] ),
                                             port:port );
}

exit( 0 );