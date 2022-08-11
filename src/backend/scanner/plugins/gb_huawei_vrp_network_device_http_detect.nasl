# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108744");
  script_version("2020-04-08T13:32:07+0000");
  script_tag(name:"last_modification", value:"2020-04-09 11:12:54 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-08 12:49:27 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Huawei VRP Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTP based detection of Huawei Versatile Routing Platform (VRP) devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/copyright/info.js";
buf = http_get_cache( item:url, port:port );

if( concl = egrep( string:buf, pattern:'(^Server\\s*:\\s*HUAWEI|var COPYRIGHT\\s*=\\s*\\{\\s*manufacturer\\s*:\\s*"Huawei")', icase:FALSE ) ) {

  version = "unknown";
  model   = "unknown";

  set_kb_item( name:"huawei/vrp/detected", value:TRUE );
  set_kb_item( name:"huawei/vrp/http/detected", value:TRUE );
  set_kb_item( name:"huawei/vrp/http/port", value:port );

  set_kb_item( name:"huawei/vrp/http/" + port + "/model", value:model );
  set_kb_item( name:"huawei/vrp/http/" + port + "/version", value:version );
  set_kb_item( name:"huawei/vrp/http/" + port + "/concluded", value:chomp( concl ) );
  set_kb_item( name:"huawei/vrp/http/" + port + "/concluded_location", value:report_vuln_url( port:port, url:url, url_only:TRUE ) );
}

exit( 0 );
