###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_gms_detection.nasl 9236 2018-03-28 08:34:34Z cfischer $
#
# Dell SonicWALL Global Management System (GMS) / Analyzer Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107120");
  script_version("$Revision: 9236 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-28 10:34:34 +0200 (Wed, 28 Mar 2018) $");
  script_tag(name:"creation_date", value:"2017-01-11 10:12:05 +0700 (Wed, 11 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dell SonicWALL Global Management System (GMS) / Analyzer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8081, 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Dell SonicWALL Global Management System (GMS) / Analyzer.

  The script sends an HTTP connection request to the server and attempts to detect the presence of Dell
  SonicWALL GMS / Analyzer and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8081 );
res = http_get_cache( item:"/", port:port );

if( res =~ "^HTTP/1\.[01] 200" && res =~ "<TITLE>(Dell )?SonicWALL Universal Management Suite" ) {

  version = "unknown";
  install = "/";

  vers = eregmatch( pattern:"<TITLE>(Dell )?SonicWALL Universal Management Suite v([0-9.]+)</TITLE>", string:res );
  if( vers[2] ) version = vers[2];

  req = http_get( port:port, item:"/sgms/auth" );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 200" && res =~ "<title>(Dell)?SonicW(ALL|all) (GMS|Global Management System) Login</title>" ) {
    product  = "Global Management System";
    cpe_part = "global_management_system";
  } else if( res =~ "^HTTP/1\.[01] 200" && "<title>Dell SonicWALL Analyzer Login</title>" >< res ) {
    product  = "Analyzer";
    cpe_part = "analyzer";
  } else {
    product  = "Unknown Product";
    cpe_part = "unknown_product";
  }

  set_kb_item( name:"sonicwall/" + cpe_part + "/version", value:version );
  set_kb_item( name:"sonicwall/ums/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/o:dell:sonicwall_" + cpe_part + ":" );
  if( ! cpe )
    cpe = "cpe:/o:dell:sonicwall_" + cpe_part;

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Dell SonicWALL " + product,
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );
