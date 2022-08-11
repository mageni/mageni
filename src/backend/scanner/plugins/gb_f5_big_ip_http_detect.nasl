# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105162");
  script_version("2022-05-09T11:19:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"creation_date", value:"2015-01-09 16:07:09 +0100 (Fri, 09 Jan 2015)");
  script_name("F5 Networks BIG-IP Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of F5 BIG-IP devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:443 );

url = "/";
buf = http_get_cache( item:url, port:port );

if( "<title>BIG-IP" >!< buf || "F5 Networks" >!< buf || "/tmui/" >!< buf ) {
  url = "/tmui/login.jsp";

  buf = http_get_cache( item:url, port:port );

  if( "<title>BIG-IP" >!< buf || "Configuration Utility" >!< buf )
    exit( 0 );
}

version = "unknown";
install = "/";
cpe = "cpe:/h:f5:big-ip";
conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

set_kb_item( name:"f5/big_ip/detected", value:TRUE );
set_kb_item( name:"f5/big_ip/http/detected", value:TRUE );

register_product( cpe:cpe, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"F5 BIG-IP",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concludedUrl:conclurl ),
             port:port );

exit( 0 );
