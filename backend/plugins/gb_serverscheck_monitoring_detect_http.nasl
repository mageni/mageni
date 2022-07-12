###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serverscheck_monitoring_detect_http.nasl 12425 2018-11-19 16:08:13Z cfischer $
#
# ServersCheck Monitoring Server Detection (HTTP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107366");
  script_version("$Revision: 12425 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 17:08:13 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-12 16:31:12 +0100 (Mon, 12 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ServersCheck Monitoring Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("ServersCheck_Monitoring_Server/banner");

  script_tag(name:"summary", value:"Detection of ServersCheck Monitoring Server using HTTP.");

  script_xref(name:"URL", value:"https://serverscheck.com/monitoring-software/");

  exit(0);
}

include( "cpe.inc" );
include( "host_details.inc" );
include( "http_func.inc" );

port = get_http_port( default: 80 );
banner = get_http_banner( port: port );

if( ! banner || banner !~ "Server: ServersCheck_Monitoring_Server" )
  exit( 0 );

version = "unknown";
set_kb_item( name: "serverscheck/monitoring_server/http/detected", value: TRUE );
set_kb_item( name: "serverscheck/monitoring_software_or_server/detected", value: TRUE );
set_kb_item( name: "serverscheck/monitoring_server/http/port", value: port );

# Server: ServersCheck_Monitoring_Server/1.1
# Server: ServersCheck_Monitoring_Server/14.0
#
# nb: Version of the server banner != the version of the Software
vers = eregmatch( pattern: "ServersCheck_Monitoring_Server/([0-9.]+)", string: banner, icase: TRUE );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  set_kb_item( name: "serverscheck/monitoring_server/http/version", value: version );
  set_kb_item( name: "serverscheck/monitoring_server/http/concluded", value: vers[0] );
}

register_and_report_cpe( app: "ServersCheck Monitoring Server", ver: version, base: "cpe:/a:serverscheck:monitoring_server:", expr: "^([0-9.]+)", insloc: "/", regPort: port, concluded: vers[0], regService: "www" );
exit( 0 );
