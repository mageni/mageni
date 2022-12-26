# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902187");
  script_version("2022-12-13T10:10:56+0000");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("VMware SpringSource tc Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of VMware SpringSource tc Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/", "/myserver", "/SStc", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item: dir + "/index.html", port:port );

  if( "<title>SpringSource tc Server</title>" >< res ) {

    version = "unknown";

    req = http_get( item: dir + "/WEB-INFO/web.xml", port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( "SpringSource tc Server runtime" >< res ) {

      ver = eregmatch( pattern:"tc Server runtime/(([0-9.]+).?([A-Za-z0-9-]+))?", string:res );
      ver = ereg_replace( pattern:"-", replace:".", string:ver[1] );
      if( ver )
        version = ver;
    }

    set_kb_item( name:"vmware/tc_server/detected", value:TRUE );
    set_kb_item( name:"vmware/tc_server/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:vmware:tc_server:" );
    if( ! cpe )
      cpe = "cpe:/a:vmware:tc_server";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"VMware SpringSource tc Server",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver ),
                 port:port );
  }
}

exit( 0 );
