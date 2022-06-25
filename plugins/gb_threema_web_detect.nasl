###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_threema_web_detect.nasl 12304 2018-11-10 12:18:34Z cfischer $
#
# Threema Web Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108453");
  script_version("$Revision: 12304 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-10 13:18:34 +0100 (Sat, 10 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-04 11:09:44 +0200 (Sat, 04 Aug 2018)");
  script_name("Threema Web Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/threema-ch/threema-web/");

  script_tag(name:"summary", value:"Detection of Threema Web.

  The script sends a connection request to the server and attempts to
  identify an installed Threema Web from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
buf = http_get_cache( item:"/", port:port );

if( buf =~ "^HTTP/1\.[01] 200" &&
      ( "<title>Threema Web</title>" >< buf ||
        "This file is part of Threema Web." >< buf ||
        # nb: The one below was added with 1.0.5:
        'content="Chat from your desktop with Threema Web and have full access to all chats, contacts and media files."' >< buf ) ) {

  install = "/";
  version = "unknown";

  set_kb_item( name:"threema-web/detected", value:TRUE );

  # Used starting from 2.0.0:
  # <li><a ng-click="ctrl.showVersionInfo('2.0.0')">Version 2.0.0 {{ ctrl.config.VERSION_MOUNTAIN }}</a></li>
  # Used from the public release 1.0.1 up to the latest 1.8.2 of the 1.x release:
  # <li>Version 1.8.2-gh</li>
  vers = eregmatch( string:buf, pattern:"(showVersionInfo\('|>Version )([0-9.]+)[^/]+" );
  if( vers[2] )
    version = vers[2];

  # Has only one line:
  # 2.1.1-gh
  # The file itself is available since around 1.4.0 (or a little bit earlier)
  # and is only used as a fallback additional to the check above.
  if( version == "unknown" ) {

    url = "/version.txt";
    req = http_get( port:port, item:url );
    res = http_keepalive_send_recv( port:port, data:req );

    # nb: The file is only shipped in the "pre-built version" so we're checking
    # first if it exists before trying to get the version from it.
    if( res =~ "^HTTP/1\.[01] 200" ) {
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      vers = eregmatch( string:res, pattern:"^([0-9.]+)(-gh)?" );
      if( vers[1] ) {
        version = vers[1];
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  # CPEs not registered yet
  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:threema:threema_web:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:threema:threema_web";

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  log_message( data:build_detection_report( app:"Threema Web",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0],
                                            concludedUrl:conclUrl ),
                                            port:port );
}

exit( 0 );