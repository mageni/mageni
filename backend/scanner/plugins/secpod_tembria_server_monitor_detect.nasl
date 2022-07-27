###############################################################################
# OpenVAS Vulnerability Test
#
# Tembria Server Monitor Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-09-29
# -updated to detect the build number
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901107");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_name("Tembria Server Monitor Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the Tembria Server Monitor version and
  saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

if( ! can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/tembria", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.asp", port:port );

  if( rcvRes =~ "HTTP/1.. 200" && '>Tembria Server Monitor<' >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:"<version>v([0-9\.]+)</version>", string:rcvRes );
    if( ver[1] ) {
      bver = eregmatch( pattern:"<buildno>([0-9.]+)</buildno>", string:rcvRes );
      if( bver[1] ) {
        version = ver[1] + "." + bver[1];
      } else {
        version = ver[1];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/tembria", value:tmp_version );
    set_kb_item( name:"tembria/server_monitor/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tembria:server_monitor:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:tembria:server_monitor';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Tembria Server Monitor",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
