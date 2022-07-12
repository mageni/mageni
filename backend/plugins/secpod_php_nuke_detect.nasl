##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_nuke_detect.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# PHP-Nuke Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.900338");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("PHP-Nuke Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed PHP-Nuke version and sets
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

cgidirs = make_list_unique( "/php-nuke", "/phpnuke", "/", "/nuke", cgi_dirs( port:port ) );
subdirs = make_list( "/", "/html" );
foreach cgidir( cgidirs ) {
  foreach subdir( subdirs ) {
    # To avoud doubled calls and calls like //cgi-bin
    if( cgidir == "/cgi-bin" && subdir == "/cgi-bin" ) continue;
    if( cgidir != "/" && subdir == "/" ) subdir = "";
    if( cgidir == "/" ) cgidir = "";
    dirs = make_list_unique( dirs, cgidir + subdir );
  }
}

foreach dir( dirs ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );
  rcvRes1 = http_get_cache( item: dir + "/admin.php", port:port );

  if( ( rcvRes =~ "HTTP/1.. 200" || rcvRes1 =~ "HTTP/1.. 200" ) &&
      ( "PHP-Nuke Powered Site" >< rcvRes ||
        '<p class="copy">PHPNUKE' >< rcvRes ||
        "PHP-Nuke</a> Copyright" >< rcvRes ||
        '<a href="http://phpnuke.org/">' >< rcvRes ||
        "PHP-Nuke Powered Site" >< rcvRes1 ||
        '<p class="copy">PHPNUKE' >< rcvRes1 ||
        "PHP-Nuke</a> Copyright" >< rcvRes1 ||
        '<a href="http://phpnuke.org/">' >< rcvRes1 ) ) {

    version = "unknown";

    foreach path( make_list( "/../Changes.txt", "/Changes.txt", "/CHANGES", "/../CHANGES" ) ) {

      sndReq = http_get( item: dir + path, port:port );
      rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

      if( "PHP-Nuke" >< rcvRes && "Version" >< rcvRes ) {
        ver = eregmatch( pattern:"Version ([0-9.]+)", string:rcvRes );
        if( ver[1] != NULL ) {
          version = ver[1];
          break;
        }
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/php-nuke", value:tmp_version );
    set_kb_item( name:"php-nuke/installed", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:phpnuke:php-nuke:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:phpnuke:php-nuke';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"PHP-Nuke",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:ver[0] ),
                                               port:port );
  }
}

exit( 0 );