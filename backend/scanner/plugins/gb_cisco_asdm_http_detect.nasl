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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105193");
  script_version("2021-07-08T06:14:58+0000");
  script_tag(name:"last_modification", value:"2021-07-08 10:00:03 +0000 (Thu, 08 Jul 2021)");
  script_tag(name:"creation_date", value:"2015-02-03 11:47:01 +0100 (Tue, 03 Feb 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Adaptive Security Device Manager (ASDM) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Adaptive Security Device Manager (ASDM).");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/admin/public/index.html";
install = "/admin";

res = http_get_cache( port:port, item:url );

if( "<title>Cisco ASDM" >!< res || "Cisco Systems" >!< res )
  exit( 0 );

version = "unknown";

# <title>Cisco ASDM 7.14(1)</title>
vers = eregmatch( pattern:"<title>Cisco ASDM ([^<]+)</title>", string:res );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  cpe_version = ereg_replace( string:version, pattern:"\(([0-9.]+)\)", replace:".\1" );
}

set_kb_item( name:"cisco/asdm/detected", value:TRUE );
set_kb_item( name:"cisco/asdm/http/detected", value:TRUE );

cpe = build_cpe( value:cpe_version, exp:"^([0-9.()]+)", base:"cpe:/a:cisco:adaptive_security_device_manager:" );
if( ! cpe )
  cpe = "cpe:/a:cisco:adaptive_security_device_manager";

register_product( cpe:cpe, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"Cisco Adaptive Security Device Manager (ASDM)",
                                          version:version, install:install, cpe:cpe,
                                          concluded:vers[0], concludedUrl:concUrl ),
             port:port );

exit(0);