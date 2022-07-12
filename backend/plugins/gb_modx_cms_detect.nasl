###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_cms_detect.nasl 8145 2017-12-15 13:31:58Z cfischer $
#
# MODX Evolution/Revolution CMS Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106458");
  script_version("$Revision: 8145 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:31:58 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-12-09 11:42:44 +0700 (Fri, 09 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MODX Evolution/Revolution CMS Detection");

  script_tag(name:"summary", value:"Detection of MODX Evolution/Revolution CMS

  The script sends a connection request to the server and attempts to detect the presence of MODX Evolution/Revolution
  CMS and to extract its version");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);
if( ! can_host_php( port:port ) ) exit(0);

foreach dir( make_list_unique( "/", "/modx", "/evolution", "/revolution", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/manager/index.php";

  res = http_get_cache( port:port, item:url );

  if( ( "http://modx.com/about/" >< res && "modx-login-username-reset" >< res ) ||
      ( "http://modx.com/" >< res && ">MODX</a>. <strong>MODX</strong>" >< res ) ||
      "<title>MODX-CMF-Manager-Login" >< res || "(MODX CMF Manager Login)</title>" >< res ||
      "<title>MODx CMF Manager Login</title>" >< res ||
      "<title>MODx CMF Manager-Login</title>" >< res ) {

    version = 'unknown';
    base_cpe = "cpe:/a:modx:unknown";
    cms_type = "Unknown Variant";
    conclUrl = NULL;

    # MODX Revolution
    url = dir + "/core/docs/changelog.txt";
    req = http_get( port:port, item:url );
    res2 = http_keepalive_send_recv( port:port, data:req );
    vers = eregmatch(pattern: "MOD(X|x) Revolution ([0-9.]+(-rc[1-9]+)?)", string:res2 );
    if( ! isnull( vers[2] ) ) {
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      version = vers[2];
      base_cpe = "cpe:/a:modx:revolution";
      cms_type = "Revolution";
    } else {
      # MODX Evolution
      url = dir + "/assets/docs/changelog.txt";
      req = http_get( port:port, item:url );
      res2 = http_keepalive_send_recv( port:port, data:req );
      vers = eregmatch(pattern: "MODX Evolution ([0-9.]+(-rc[1-9]+)?)", string:res2 );
      if( ! isnull( vers[1] ) ) {
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        version = vers[1];
        base_cpe = "cpe:/a:modx:evolution";
        cms_type = "Evolution";
      }
    }

    # Second try if we don't know the CMS variant yet.
    if( cms_type == "Unknown Variant" ) {
      # MODX Revolution
      if( "MODX Revolution</title>" >< res || "<h2>MODx Revolution</h2>" >< res ) {
        base_cpe = "cpe:/a:modx:revolution";
        cms_type = "Revolution";
      } else {
        # MODX Evolution
        url = dir + "/README.md";
        req = http_get( port:port, item:url );
        res2 = http_keepalive_send_recv( port:port, data:req );
        if( "# MODX Evolution" >< res2 ) {
          base_cpe = "cpe:/a:modx:evolution";
          cms_type = "Evolution";
          conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        } else if( ">MODx CMF Team</a>" >< res ) {
          base_cpe = "cpe:/a:modx:evolution";
          cms_type = "Evolution";
        }
      }
    }

    set_kb_item( name:"modx_cms/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+(-rc[1-9]+)?)", base:base_cpe + ":" );
    if( ! cpe )
      cpe = base_cpe;

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"MODX " + cms_type + " CMS",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );
