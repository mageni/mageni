###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpwiki_detect.nasl 11224 2018-09-04 12:57:17Z cfischer $
#
# PhpWiki Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806033");
  script_version("$Revision: 11224 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-04 14:57:17 +0200 (Tue, 04 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-09-02 11:34:10 +0530 (Wed, 02 Sep 2015)");
  script_name("PhpWiki Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of PhpWiki.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");


port = get_http_port(default:80);

if( ! can_host_php( port:port ) ) exit(0);

foreach dir( make_list_unique( "/", "/phpwiki", "/wiki", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "HTTP/1.. 200" && 'content="PhpWiki' >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:'PHPWIKI_VERSION" content="([0-9A-Z.]+)', string:rcvRes );
    if( ver[1] ) version = ver[1];

    tmp_version = version + " under " + install;

    set_kb_item( name:"www/" + port + "/PhpWiki", value:tmp_version );
    set_kb_item( name:"PhpWiki/Installed", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9A-Z.]+)", base:"cpe:/a:phpwiki:phpwiki:" );
    if( ! cpe )
      cpe = "cpe:/a:phpwiki:phpwiki";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"PhpWiki",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );