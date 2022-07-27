###############################################################################
# OpenVAS Vulnerability Test
# $Id: serendipity_detect.nasl 8145 2017-12-15 13:31:58Z cfischer $
#
# Serendipity Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-09-21
# Updated to detect the recent versions
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100112");
  script_version("$Revision: 8145 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:31:58 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-04-08 12:09:59 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Serendipity Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Serendipity.

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

foreach dir( make_list_unique( "/serendipity", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( buf == NULL ) continue;

  if( buf =~ "HTTP/1\.. 200" && (
      egrep( pattern:"Powered.by.*(Serendipity|>s9y</a>)", string:buf, icase:TRUE ) ||
      '<meta name="generator" content="Serendipity' >< buf ) ) {

    version = "unknown";

    vers = eregmatch( string:buf, pattern:"Serendipity v\.([0-9.]+[-a-zA-Z0-9]*)", icase:TRUE );
    if( isnull( vers[1] ) ) {

      url = dir + "/serendipity_admin.php";
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      if( "Powered by Serendipity" >< buf ) {
        vers = eregmatch( string:buf, pattern:"Serendipity ([0-9.]+[-a-zA-Z0-9]*)", icase:TRUE );
        if( vers[1] ) version = vers[1];
      }
    } else {
      version = vers[1];
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/serendipity", value:tmp_version );
    set_kb_item( name:"Serendipity/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:s9y:serendipity:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:s9y:serendipity';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Serendipity",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );