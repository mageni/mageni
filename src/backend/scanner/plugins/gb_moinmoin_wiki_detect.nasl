###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_wiki_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# MoinMoin Wiki Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800170");
  script_version("$Revision: 9633 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_name("MoinMoin Wiki Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of MoinMoin Wiki.

  This script detects the installed version of MoinMoin Wiki
  and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

function _SetCpe( vers, port, dir, concl, conclUrl ) {

  local_var vers, port, tmp_version, dir, concl, conclUrl;

  tmp_version = vers + " under " + dir;
  set_kb_item( name:"www/" + port + "/moinmoinWiki", value:tmp_version );
  set_kb_item( name:"moinmoinWiki/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.a-z]+)", base:"cpe:/a:moinmo:moinmoin:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:moinmo:moinmoin';

  register_product( cpe:cpe, location:dir, port:port );
  log_message( data:build_detection_report( app:"moinmoinWiki",
                                            version:vers,
                                            install:dir,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:concl ),
                                            port:port );
}

port = get_http_port( default:8080 );

banner = get_http_banner( port:port );
if( "erver: MoinMoin" >< banner ) {
  bannerIdentified = TRUE;
  vers = eregmatch( pattern:"erver: MoinMoin ([0-9.a-z]+) release", string:banner );
  if( vers[1] ) {
    bannerVersion = TRUE;
    _SetCpe( vers:vers[1], port:port, dir:"/", concl:vers[0] );
  }
}

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/Moin", "/moin", "/wiki", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  if( rootInstalled ) break;

  url1 = dir + "/SystemInfo";
  req1 = http_get( item:url1, port:port );
  res1 = http_keepalive_send_recv( port:port, data:req1 );

  res2 = http_get_cache( item:"/", port:port );

  if( ( res1 =~ "^HTTP/1\.[01] 200" && "SystemInfo" >< res1 && ">MoinMoin" >< res1 ) ||
        "This site uses the MoinMoin Wiki software." >< res2 || ">MoinMoin Powered<" >< res2 ) {

    version = "unknown";
    flag = TRUE;
    if( install == "/" ) rootInstalled = TRUE;
    if( bannerVersion && install == "/" ) continue;

    vers = eregmatch( pattern:"(Release|Version) ([0-9.a-z]+) \[Revision release\]", string:res1 );
    if( vers[2] ) {
      version  = vers[2];
      conlcUrl = report_vuln_url( port:port, url:url1, url_only:TRUE );
    } else {
      # MoinMoin/config/__init__.py:url_prefix_static = '/moin_static' + version.release_short
      # so we can conclude the version from css/js links like:
      # <link rel="stylesheet" type="text/css" charset="utf-8" media="all" href="/moin_static194/modern/css/common.css">
      vers = eregmatch( pattern:'(src|href)="/moin_static([0-9]+)/', string:res2 );
      if( vers[2] ) {
        short_vers = vers[2];
        for( i = 0; i < strlen( short_vers ); i++ ) {
          if( i == 0 ) {
            version = short_vers[i];
          } else {
            version += "." + short_vers[i];
          }
        }
      }
    }
    _SetCpe( vers:version, port:port, dir:install, concl:vers[0], conclUrl:conlcUrl );
  }
}

if( bannerIdentified && ! flag ) {
  _SetCpe( vers:version, port:port, dir:install, concl:vers[0] );
}

exit( 0 );