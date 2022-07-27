# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140244");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-02-15T11:50:31+0000");
  script_tag(name:"last_modification", value:"2022-02-16 11:08:17 +0000 (Wed, 16 Feb 2022)");
  script_tag(name:"creation_date", value:"2017-04-11 13:15:09 +0200 (Tue, 11 Apr 2017)");
  script_name("Moxa MXview Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Moxa MXview.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

url = "/index_en.htm";
buf = http_get_cache( item:url, port:port );

if( "<title>MXview</title>" >< buf && "MXviewClientSetup" >< buf && "Moxa Inc." >< buf )
  found = TRUE;

if( ! found ) {

  url = "/";
  buf = http_get_cache( item:url, port:port );

  # <img class="logo" src="/../assets/img/MoxaLogo_Green_Version.png">
  if( "<title>MXview</title>" >< buf && "img/MoxaLogo" >< buf )
    found = TRUE;
}

if( found ) {

  version = "unknown";
  install = "/";
  cpe = "cpe:/a:moxa:mxview";

  set_kb_item( name:"moxa/mxview/detected", value:TRUE );
  set_kb_item( name:"moxa/mxview/http/detected", value:TRUE );

  # nb: System requirements is a Windows based system according to the vendor.
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows",
                          desc:"Moxa MXview Detection (HTTP)", runs_key:"windows" );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Moxa MXview",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:http_report_vuln_url( port:port, url:url, url_only:TRUE ) ),
               port:port );
}

exit( 0 );
