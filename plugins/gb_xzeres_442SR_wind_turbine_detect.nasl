###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xzeres_442SR_wind_turbine_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# XZERES 442SR Wind Turbine Remote Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807020");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-01-04 13:19:12 +0530 (Mon, 04 Jan 2016)");
  script_name("XZERES 442SR Wind Turbine Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  XZERES 442SR Wind Turbine.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if( ! can_host_php( port:port ) ) exit(0);

rcvRes = http_get_cache( item: "/", port:port );

if( rcvRes && '<title> XZERES Wind' >< rcvRes ) {

    install = "/";
    version = "unknown";

    set_kb_item( name:"www/" + port + "/442SR/Wind/Turbine", value:version );
    set_kb_item( name:"442SR/Wind/Turbine/Installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/h:xzeres:442sr:" );
    if( ! cpe )
      cpe = "cpe:/h:xzeres:442sr";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"442SR Wind Turbine",
                                              version:version,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
}

exit( 0 );