###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cradlepoint_router_http_detect.nasl 12813 2018-12-18 07:43:29Z ckuersteiner $
#
# Cradlepoint Routers Detection (HTTP)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112451");
  script_version("$Revision: 12813 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 08:43:29 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-06 10:55:11 +0100 (Thu, 06 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cradlepoint Routers Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Cradlepoint routers.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );
buf  = http_get_cache( item:"/login/", port:port );

if( buf =~ "^HTTP/1\.[01] 200" &&
    ( 'manufacturer: "Cradlepoint Inc."' >< buf ||
    ( "cplogin = window.cplogin" >< buf && 'cplogin.state' >< buf ) )
  ) {

  model      = "unknown";
  fw_version = "unknown";

  mod = eregmatch( pattern:'cplogin.model = "([A-Za-z0-9-]+)";', string:buf, icase:TRUE );
  if( mod[1] ) {
    model = mod[1];
    set_kb_item( name:"cradlepoint/router/http/" + port + "/concluded", value:mod[0] );
  }

  fw = eregmatch( pattern:'cplogin.version = "([0-9.]+) ', string:buf );
  if( fw[1] ) {
    fw_version = fw[1];
  }

  set_kb_item( name:"cradlepoint/router/http/" + port + "/model", value:model );
  set_kb_item( name:"cradlepoint/router/http/" + port + "/fw_version", value:fw_version );
  set_kb_item( name:"cradlepoint/router/http/detected", value:TRUE );
  set_kb_item( name:"cradlepoint/router/http/port", value:port );
  set_kb_item( name:"cradlepoint/router/detected", value:TRUE );
}

exit( 0 );
