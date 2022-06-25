###############################################################################
# OpenVAS Vulnerability Test
# $Id: GlassFish_detect.nasl 12985 2019-01-09 07:04:34Z cfischer $
#
# GlassFish Server Detection
#
# Authors:
# Michael Meyer
#
# Updated by: Antu Sanadi <santu@secpod.com> on 2010-01-31
# Updated to detect recent versions (3.x)
# Updated to to read the data from index.html, on 2012-01-06
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2012-05-07
# - Updated according to CR57
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
  script_oid("1.3.6.1.4.1.25623.1.0.100190");
  script_version("$Revision: 12985 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-09 08:04:34 +0100 (Wed, 09 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("GlassFish Server Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080, 8181, 4848);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Oracle GlassFish Server.

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );

buf = http_get_cache( item:"/index.html", port:port );

req2 = http_get( item:"/i_dont_exist", port:port );
buf2 = http_keepalive_send_recv( port:port, data:req2 );

if( ( "<title>GlassFish Server" ><buf && "Server Running</title>" >< buf ) ||
      egrep( pattern: 'Server:.*GlassFish.*', string: buf, icase: TRUE ) ||
      ( "<title>GlassFish Server" >< buf2 && "Error report</title>" >< buf2  ) ||
        "Log In to GlassFish Administration Console" >< buf ) {

  vers = "unknown";

  #Banner:
  #X-Powered-By: Servlet/3.0 JSP/2.2 (GlassFish Server Open Source Edition 3.1.2.2 Java/Oracle Corporation/1.7)
  #Server: GlassFish Server Open Source Edition 3.1.2.2
  #Server: GlassFish Server Open Source Edition  4.1
  #X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  4.1  Java/Oracle Corporation/1.7)

  version = eregmatch( string:buf, pattern:'Server:.*GlassFish[^0-9]+v([0-9.]+)', icase:TRUE );
  if( isnull( version[1] ) ) {
    version = eregmatch( string:buf, pattern:"GlassFish Server( Open Source Edition)?( )? ([0-9.]+)", icase:TRUE );
    if( ! isnull( version[3] ) ) {
      vers = version[3];
    } else {
      version = eregmatch( string:buf2, pattern:"GlassFish Server( Open Source Edition)?( )? ([0-9.]+)", icase:TRUE );
      if( ! isnull( version[3] ) ) vers = version[3];
    }
  } else {
    vers = version[1];
  }

  if( egrep( pattern:"Location:.*login.jsf", string:buf ) ||
    ( egrep( pattern:"Log In to.*GlassFish", string:buf ) && "<title>Login" >< buf ) ) {

    report = "The GlassFish Administration Console is running at this port.";
    set_kb_item( name:"www/" + port + "/GlassFishAdminConsole", value:TRUE );
    set_kb_item( name:"GlassFishAdminConsole/port", value:port );
  }

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:oracle:glassfish_server:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:oracle:glassfish_server";

  register_product( cpe:cpe, location:"/", port:port, service:"www" );

  set_kb_item( name:"GlassFish/installed", value:TRUE );
  set_kb_item( name:"glassfish_or_sun_java_appserver/installed", value:TRUE );

  log_message( data:build_detection_report( app:"GlassFish Server", version:vers, install:"/", cpe:cpe, concluded:version[0], extra:report ),
               port:port );
}

exit( 0 );