##############################################################################
# OpenVAS Vulnerability Test
#
# LightNEasy Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900371");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("LightNEasy Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of LightNEasy and
  sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");


port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/lne", "/lightneasy", "/nodatabase", "/sqlite", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get( item:dir + "/LightNEasy.php?do=login", port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );
  rcvRes2 = http_get_cache( item: dir + "/index.php", port:port );

  if( ( rcvRes =~ "HTTP/1.. 200" && ( "generator' content='LightNEasy" >< rcvRes || "LightNEasy.php?page=index" >< rcvRes || "css/lightneasy.css" >< rcvRes ) ) ||
      ( rcvRes2 =~ "HTTP/1.. 200" && ( "generator' content='LightNEasy" >< rcvRes2 || "LightNEasy.php?do=login" >< rcvRes2 || "css/lightneasy.css" >< rcvRes2 ) ) ) {

    version = "unknown";

    ver = eregmatch( pattern:"LightNEasy ([0-9.]+)", string:rcvRes );
    if( ver[1] != NULL ) {
      version = ver[1];
    } else {
      ver = eregmatch( pattern:"LightNEasy( Mini)? ([0-9.]+)", string:rcvRes2 );
      if( ver[2] != NULL ) version = ver[2];
    }

    set_kb_item( name:"lightneasy/detected", value:TRUE );
    tmp_version = version + " under " + install;

    if( "SQLite" >< rcvRes || "sqlite" >< rcvRes ) {

      set_kb_item( name:"www/"+ port + "/LightNEasy/Sqlite", value:tmp_version );

      cpe = 'cpe:/a:sqlite:sqlite';

      register_product( cpe:cpe, location:install, port:port );

      log_message( data: build_detection_report( app:"SQLite",
                                                 install:install,
                                                 cpe:cpe),
                                                 port:port );
    } else {
      set_kb_item( name:"www/"+ port + "/LightNEasy/NoDB", value:tmp_version );
    }

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:lightneasy:lightneasy:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:lightneasy:lightneasy';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"LightNEasy",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:ver[0] ),
                                               port:port );
  }
}

exit( 0 );
