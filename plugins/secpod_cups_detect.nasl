###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cups_detect.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# CUPS Version Detection
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900348");
  script_version("$Revision: 10922 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_name("CUPS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl", 'find_service.nasl');
  script_require_ports("Services/www", 631);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Common Unix Printing System (CUPS)

  This script sends HTTP GET request and try to get the version from the response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:631 );

rcvRes = http_get_cache( port:port, item:"/" );

if( "Server: CUPS/" >< rcvRes || rcvRes =~ "<TITLE>(Forbidden|Home|Not Found|Bad Request) - CUPS.*</TITLE>" ) {

  version = "unknown";
  location = "/";

  ver = eregmatch( pattern:"<title>.*CUPS v?([0-9.RCB]+).*</title>", string:rcvRes, icase:TRUE );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
  } else {
    ver = eregmatch( pattern:"Server: CUPS/([0-9.RCB]+)", string:rcvRes, icase:TRUE );
    if( ! isnull( ver[1] ) ) version = ver[1]; # Only getting the major version here
  }

  set_kb_item( name:"www/"+ port + "/CUPS", value:version );
  set_kb_item( name:"CUPS/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)([a-z0-9]+)?", base:"cpe:/a:apple:cups:" );
  if( ! cpe )
    cpe = "cpe:/a:apple:cups";

  register_product( cpe:cpe, location:location, port:port );

  log_message( data:build_detection_report( app:"CUPS",
                                            version:version,
                                            install:location,
                                            port:port,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
