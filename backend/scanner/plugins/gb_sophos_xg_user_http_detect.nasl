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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105626");
  script_version("2022-03-30T12:11:10+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-04-27 12:37:42 +0200 (Wed, 27 Apr 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sophos XG Firewall Detection (HTTP, User Portal)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of a Sophos XG Firewall from the user
  portal.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/userportal/webpages/myaccount/login.jsp";
res = http_get_cache( item:url, port:port );

if( res !~ "^HTTP/1\.[01] 200" || "<title>Sophos</title>" >!< res ||
    'Cyberoam.setContextPath("/userportal");' >!< res )
  exit( 0 );

url1 = "/javascript/lang/English/common.js";
res1 = http_get_cache( item:url1, port:port );
if( res1 !~ "Sophos [^ ]*Firewall" && "Cyberroam" >!< res1 )
  exit( 0 );

set_kb_item( name:"sophos/xg_firewall/detected", value:TRUE );
set_kb_item( name:"sophos/xg_firewall/http-user/detected", value:TRUE );
set_kb_item( name:"sophos/xg_firewall/http-user/port", value:port );

version = "unknown";

# example: ver=17.5.10.620 (620 seems to be the "build")
# Note: at least since release 18 the version is not included anymore
vers = eregmatch( pattern:'ver=([0-9]+\\.[^"\' ]+)', string:res );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  set_kb_item( name:"sophos/xg_firewall/http-user/" + port + "/concluded", value:vers[0] );
  set_kb_item( name:"sophos/xg_firewall/http-user/" + port + "/concludedUrl",
               value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
}

set_kb_item( name:"sophos/xg_firewall/http-user/" + port + "/version", value:version );

exit( 0 );
