###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_tutos_detect.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# TUTOS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.111040");
  script_version("$Revision: 10899 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-10-07 14:00:00 +0200 (Wed, 07 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("TUTOS Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP
  request to the server and attempts to extract the version from
  the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );

if( !can_host_php( port:port ) ) exit( 0 );

dirs = make_list_unique( "/", "/tutos", cgi_dirs( port:port ) );

foreach dir ( dirs ) {

  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item: dir + "/php/mytutos.php", port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  buf2 = http_get_cache( item: dir + "/ChangeLog", port:port );

  if( "<title>TUTOS" >< buf || "Please send all your feedback to gokohnert" >< buf2 ) {

    version = 'unknown';

    ver = eregmatch( pattern:'title="TUTOS ([0-9.]+)', string:buf );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
    } else {
      ver = eregmatch( pattern:"Release ([0-9.]+)", string:buf2 );
      if( ! isnull( ver[1] ) ) version = ver[1];
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tutos:tutos:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:tutos:tutos';

    set_kb_item( name:"www/" + port + "/tutos", value:version );
    set_kb_item( name:"tutos/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"TUTOS",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded: ver[0]),
                                               port:port);
  }
}

exit(0);
