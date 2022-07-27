##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_advantech_webaccess_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# Advantech WebAccess Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804429");
  script_version("2019-04-11T10:25:03+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-11 10:25:03 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2014-04-16 14:24:35 +0530 (Wed, 16 Apr 2014)");

  script_name("Advantech WebAccess Version Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Advantech WebAccess.

The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include( "http_func.inc" );
include( "host_details.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default:80 );
if( ! can_host_asp( port: port ) )
  exit( 0 );

res = http_get_cache( item: "/broadWeb/bwRoot.asp", port: port );
if( ! res || "Advantech WebAccess" >!< res )
  exit( 0 );

set_kb_item( name: "advantech/webaccess/detected", value: TRUE );
set_kb_item( name: "advantech/webaccess/http/" + port + "/detected", value: TRUE );

version = "unknown";
concluded = "HTTP Request";

# <div class="version">
#   Software Build : 8.3.5
# </div>
vers = eregmatch( pattern:"Software Build : ([0-9.-]+)", string: res );
if( ! vers[1] ) {
  vers = eregmatch( pattern:"class=e5>.*: ([0-9.-]+)", string: res );
}

if( ! isnull( vers[1] ) ) {
  version = str_replace( string: vers[1], find: "-", replace: "." );
} else {
  vers = eregmatch( pattern: 'class="version">.*: ([0-9.-]+)', string: res );
  if ( ! isnull( vers[1] ) ) {
    version = str_replace( string: vers[1], find: "-", replace: "." );
  }
}

set_kb_item( name: "advantech/webaccess/http/" + port + "/version", value: version );
set_kb_item( name: "advantech/webaccess/http/" + port + "/concluded", value: vers[0] );
set_kb_item( name: "advantech/webaccess/http/" + port + "/location", value: "/broadWeb/" );
set_kb_item( name: "advantech/webaccess/http/port", value: port );

exit( 0 );