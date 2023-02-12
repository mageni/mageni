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
  script_oid("1.3.6.1.4.1.25623.1.0.105622");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-04-26 11:59:19 +0200 (Tue, 26 Apr 2016)");
  script_name("Sophos Cyberoam Central Console (CCC) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Sophos Cyberoam Central Console
  (CCC).");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = "/CCC/login.html";
buf = http_get_cache( item:url, port:port );

if( "<title>Cyberoam Central Console</title>" >< buf && "/CCC/Controller" >< buf && ">www.cyberoam.com<" >< buf ) {

  set_kb_item( name:"sophos/cyberoam_central_console/detected", value:TRUE );
  set_kb_item( name:"sophos/cyberoam_central_console/http/detected", value:TRUE );

  cpe = "cpe:/a:cyberoam:cyberoam_central_console";
  install = "/CCC";
  version = "unknown";
  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Sophos Cyberoam Central Console (CCC)", version:version, install:install,
                                            cpe:cpe, concludedUrl:conclUrl ),
               port:port );
}

exit( 0 );
