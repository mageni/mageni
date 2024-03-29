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
  script_oid("1.3.6.1.4.1.25623.1.0.105387");
  script_version("2022-12-08T10:30:31+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-08 10:30:31 +0000 (Thu, 08 Dec 2022)");
  script_tag(name:"creation_date", value:"2015-09-25 13:13:41 +0200 (Fri, 25 Sep 2015)");
  script_name("Open-Xchange (OX) App Suite Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.open-xchange.com/products/ox-app-suite/");

  script_tag(name:"summary", value:"HTTP based detection of Open-Xchange (OX) App Suite.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = "/appsuite/apps/io.ox/help/style.less";
buf = http_get_cache( item:url, port:port );
if( ! buf && buf !~ "Open-Xchange Inc\.,|OX Software GmbH" )
  exit( 0 );

conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

url = "/appsuite/signin";
buf = http_get_cache( item:url, port:port );
if( ! buf || "window.ox" >!< buf || "io-ox-copyright" >!< buf )
  exit( 0 );

conclurl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
cpe = "cpe:/a:open-xchange:open-xchange_appsuite";
version = "unknown";
install = "/appsuite";

set_kb_item( name:"open-xchange/app_suite/detected", value:TRUE );
set_kb_item( name:"open-xchange/app_suite/http/detected", value:TRUE );

# <script src="v=7.10.3-25.20210105.114712/boot.js"></script>
# <script src="v=7.8.2-4.20160712.011310/boot.js">
# <script src="v=7.8.2-32.20180509.092606/precore.js" defer="defer"></script>
# <script src="v=7.10.6-20.20221018.014247/boot.js"></script>
# <script src="v=7.8.3-13.20170217.093016/boot.js"></script>
vers = eregmatch( pattern:'script src="v=([^-]+)-([0-9]+)', string:buf );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  cpe += ":" + version;
}

if( ! isnull( vers[2] ) )
  set_kb_item( name:"open-xchange/app_suite/" + port + "/revision", value:vers[2] );

register_product( cpe:cpe, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"Open-Xchange (OX) App Suite", version:version, install:install,
                                          cpe:cpe, concluded:vers[0], concludedUrl:conclurl ),
             port:port );

exit(0);
