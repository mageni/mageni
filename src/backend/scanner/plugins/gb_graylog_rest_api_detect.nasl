# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105758");
  script_version("2022-08-10T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-08-10 10:11:40 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-06-10 13:02:29 +0200 (Fri, 10 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Graylog Detection (REST API)");

  script_tag(name:"summary", value:"HTTP based detection of the Graylog REST API endpoint.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 12900);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:12900 );

url = "/system/cluster/node";

res = http_get_cache( port:port, item:url );

if( "X-Graylog-Node-ID" >!< res || '{"cluster_id":' >!< res || "is_master" >!< res ) {
  url = "/api/";

  res = http_get_cache( port:port, item:url );

  if( '{"cluster_id":' >!< res )
    exit( 0 );
}

version = "unknown";

set_kb_item( name:"graylog/detected", value:TRUE );
set_kb_item( name:"graylog/rest_api/detected", value:TRUE );
set_kb_item( name:"graylog/rest_api/port", value:port );
set_kb_item( name:"graylog/rest_api/" + port + "/concludedUrl", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );

# "version":"2.4.7+9116ead",
vers = eregmatch( pattern:'"version":"([^"]+)"', string:res );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  set_kb_item( name:"graylog/rest_api/" + port + "/concluded", value:vers[0] );
}

id = eregmatch( pattern:'X-Graylog-Node-ID: ([^\r\n ]+)', string:res );
if( ! isnull( id[1] ) )
  set_kb_item( name:"graylog/http/" + port + "/extra", value:"Graylog Node ID: " + id[1] );

set_kb_item( name:"graylog/http/" + port + "/version", value:version );

exit( 0 );
