###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_squid_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# Squid Proxy Server Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Veerendra G.G <veerendragg@secpod.com>
# Updated : According to CR57 and new nvt style
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
  script_oid("1.3.6.1.4.1.25623.1.0.900611");
  script_version("$Revision: 10898 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-07 09:44:25 +0200 (Tue, 07 Apr 2009)");
  script_name("Squid Proxy Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod.");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "proxy_use.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of squid.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_kb_item( "Services/http_proxy" );
if( ! port ) port = 3128;
if( ! get_port_state( port ) ) port = 8080;
if( ! get_port_state( port ) ) exit( 0 );

req     = http_get( item:"http://www.$$$$$", port:port );
res     = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
banner  = get_http_banner( port:port );
pattern = "^Server: squid";

if( data = egrep( pattern:pattern, string:res, icase:TRUE )  ) {
  installed = TRUE;
} else {
  if( data = egrep( pattern:pattern, string:banner, icase:TRUE )  ) {
    installed = TRUE;
  }
}

if( installed ) {

  vers    = "unknown";
  install = port + "/tcp";
  version = eregmatch( pattern:"^Server: squid/([0-9a-zA-Z.]+)", string:data, icase:TRUE );

  if( version[1] ) {
    vers = version[1];
    set_kb_item( name:"www/" + port + "/Squid", value:vers );
  }

  set_kb_item( name:"squid_proxy_server/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.]+.[a-zA-Z0-9]+)", base:"cpe:/a:squid-cache:squid:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:squid-cache:squid";

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Squid Proxy Server",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0] ),
                                            port:port );
}

exit( 0 );
