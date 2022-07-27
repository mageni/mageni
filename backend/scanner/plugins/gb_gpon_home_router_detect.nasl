###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gpon_home_router_detect.nasl 12593 2018-11-30 08:49:46Z cfischer $
#
# GPON Home Router Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.113169");
  script_version("$Revision: 12593 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 09:49:46 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-05-03 16:40:00 +0200 (Thu, 03 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("GPON Home Router Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 81, 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"GPON Home Router Detection.");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 8080 );

res = http_get_cache( port: port, item: "/login.html" );
res2 = http_get_cache( port: port, item: "/" );

if( res =~ '<form id="XForm" name="XForm" method="post" action="/GponForm/LoginForm">' ||
    res =~ 'var XOntName = \'GPON Home Gateway\';' ||
    ( res2 =~ "^HTTP/1\.[01] 200" &&
        # nb: Both have line breaks in between
      ( res2 =~ "<title>.*GPON Home Gateway.*</title>" ||
        res2 =~ "<td colspan.*GPON Home Gateway.*</td>" )
    )
  ) {

  set_kb_item( name: "gpon/home_router/detected", value: TRUE );

  CPE = "cpe:/o:gpon:home_router";

  register_and_report_cpe( app: "GPON Home Router",
                           cpename: CPE,
                           insloc: "/",
                           regPort: port );
}

exit( 0 );