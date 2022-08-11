###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco FirePOWER Management Center Detection (HTTP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105521");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-04-03T05:47:31+0000");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2016-01-19 17:03:19 +0100 (Tue, 19 Jan 2016)");

  script_name("Cisco FirePOWER Management Center Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs a HTTP based detection of Cisco FirePOWER Management Center.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443 );

res = http_get_cache( port:port, item: "/login.cgi" );

if( "<title>Login</title>" >!< res || "Cisco" >!< res || ("askToClearSession" >!< res && "SF.Modal" >!< res))
  exit( 0 );

version = "unknown";
build = "unknown";
model = "unknown";

# Newer versions don't include this anymore
vers = eregmatch( pattern:'\\?v=([0-9.]+)-([0-9]+)', string:res );

if( ! isnull( vers[1] ) )
  version = vers[1];

if( ! isnull( vers[2] ) )
  build = vers[2];

set_kb_item( name:"cisco/firepower_management_center/detected", value:TRUE );
set_kb_item( name:"cisco/firepower_management_center/http/port", value:port );
set_kb_item( name:"cisco/firepower_management_center/http/" + port + "/model", value:model );
set_kb_item( name:"cisco/firepower_management_center/http/" + port + "/version", value:version );
set_kb_item( name:"cisco/firepower_management_center/http/" + port + "/build", value:build );

exit( 0 );
