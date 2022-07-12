##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tikiwiki_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Tiki Wiki CMS Groupware Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated by Rachana Shetty <srachana@secpod.com> on 2011-12-06
# - Updated to detect the recent versions and CR 57
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
  script_oid("1.3.6.1.4.1.25623.1.0.901001");
  script_version("$Revision: 10894 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Tiki Wiki CMS Groupware Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://tiki.org/");

  script_tag(name:"summary", value:"Detection of Tiki Wiki CMS Groupware, a open source web application
  is a wiki-based CMS.

  The script sends a connection request to the web server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/tikiwiki", "/tiki", "/wiki", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item:dir + "/tiki-index.php", port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res =~ "HTTP/1.. 200" && ( "TikiWiki" >< res || "Tiki Wiki CMS" >< res ) ) {

    version = "unknown";

    ver = eregmatch(pattern:"TikiWiki ([0-9.]+)", string:res);

    if( ver[1] != NULL ) {
      version = ver[1];
    } else {
      url = dir + "/README";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      if( res =~ "HTTP/1.. 200" ) {
        ver = eregmatch( pattern:"[v|V]ersion ([0-9.]+)", string:res );
        if( ver[1] != NULL ) {
          version = ver[1];
          conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    url = dir + "/tiki-install.php";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if( res =~ "HTTP/1.. 200" && "<title>Tiki Installer" >< res ) {
      extra = "The Tiki Installer is available at " + report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"TikiWiki/" + port + "/Ver", value:tmp_version );
    set_kb_item( name:"TikiWiki/installed", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:tiki:tikiwiki_cms/groupware:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:tiki:tikiwiki_cms/groupware';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"Tiki Wiki CMS Groupware",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               extra:extra,
                                               concludedUrl:conclUrl,
                                               concluded:ver[0] ),
                                               port:port );
  }
}

exit( 0 );