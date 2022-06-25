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
  script_oid("1.3.6.1.4.1.25623.1.0.105576");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-09-23T09:17:45+0000");
  script_tag(name:"last_modification", value:"2020-09-23 09:17:45 +0000 (Wed, 23 Sep 2020)");
  script_tag(name:"creation_date", value:"2016-03-17 16:05:49 +0100 (Thu, 17 Mar 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco UCS Director Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Cisco UCS Director.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:443 );

url = "/app/ui/login.jsp";
buf = http_get_cache( item:url, port:port );

if( "<title>Login</title>" >!< buf || ">Cisco UCS Director<" >!< buf || "Cisco Systems, Inc." >!< buf )
  exit( 0 );

version = "unknown";

set_kb_item( name:"cisco/ucs_director/detected", value:TRUE );
set_kb_item( name:"cisco/ucs_director/http/port", value:port );
set_kb_item( name:"cisco/ucs_director/http/" + port + "/version", value:version );
set_kb_item( name:"cisco/ucs_director/http/" + port + "/concludedUrl",
             value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );

exit( 0 );
