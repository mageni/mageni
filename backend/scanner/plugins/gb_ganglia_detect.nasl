###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ganglia_detect.nasl 10929 2018-08-11 11:39:44Z cfischer $
#
# Ganglia Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_tag(name:"cvss_base", value:"0.0");
  script_oid("1.3.6.1.4.1.25623.1.0.103534");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10929 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-11 13:39:44 +0200 (Sat, 11 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-08-13 12:20:02 +0200 (Mon, 13 Aug 2012)");
  script_name("Ganglia Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Ganglia.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique("/", "/ganglia","/gang", "/gweb", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( buf == NULL )continue;

  if( ( "<title>ganglia" >< tolower( buf ) && "Ganglia Web Backend" >< buf) || "There was an error collecting ganglia data" ><buf ) {

    vers = "unknown";

    version = eregmatch( string:buf, pattern:"Ganglia Web Frontend version ([0-9.]+)", icase:TRUE );

    if( ! isnull( version[1] ) ) {
      vers = chomp( version[1] );
    }

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/ganglia", value:tmp_version );
    set_kb_item( name:"ganglia/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:ganglia:ganglia-web:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:ganglia:ganglia-web';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Ganglia",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
  }
}

exit( 0 );
