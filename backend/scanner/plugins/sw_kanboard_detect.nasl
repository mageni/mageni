###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_kanboard_detect.nasl 7166 2017-09-18 09:14:09Z cfischer $
#
# Kanboard Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111062");
  script_version("$Revision: 7166 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 11:14:09 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2015-12-03 15:00:00 +0100 (Thu, 03 Dec 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Kanboard Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request
  to the server and attempts to detect the applicaton from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/kanboard", cgi_dirs(port:port) ) ) {

  if( rootInstalled ) break;
  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item: dir + "/?controller=auth&action=login", port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  req2 = http_get( item: dir + "/jsonrpc.php", port:port );
  buf2 = http_keepalive_send_recv( port:port, data:req2 );

  req3 = http_get( item: dir + "/?controller=user&action=login", port:port );
  buf3 = http_keepalive_send_recv( port:port, data:req3 );

  if( ( "<title>Login</title>" >< buf && "data-status-url" >< buf ) ||
      ( '{"jsonrpc":"' >< buf2 && 'Parse error"}' >< buf2 ) ||
      "<title>Login - Kanboard</title>" >< buf3 || "Internal Error: Action not implemented" >< buf3 ) {

    version = 'unknown';
    if( dir == "" ) rootInstalled = 1;

    buf = http_get_cache( item: dir + "/ChangeLog", port:port );

    ver = eregmatch( pattern:"Version ([0-9.]+)", string:buf );

    if( ! isnull( ver[1] ) ) version = ver[1];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:kanboard:kanboard:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:kanboard:kanboard';

    set_kb_item( name:"www/" + port + "/kanboard", value:version );
    set_kb_item( name:"kanboard/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Kanboard",
                                              version:version,
                                              concluded:ver[0],
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );