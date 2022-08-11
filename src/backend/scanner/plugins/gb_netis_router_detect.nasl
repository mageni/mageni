###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netis_router_detect.nasl 12364 2018-11-15 10:19:32Z jschulte $
#
# Netis Router Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.113303");
  script_version("$Revision: 12364 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 11:19:32 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-15 10:13:37 +0100 (Thu, 15 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Netis Router Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks if the target device is a Netis Router
  and if so, tries to figure out the installed firmware version.");

  script_xref(name:"URL", value:"http://www.netis-systems.com/Home/info/id/2.html");
  script_xref(name:"URL", value:"http://www.netis-systems.com/Business/info/id/2.html");

  exit(0);
}

CPE = "cpe:/h:netis:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );
include( "cpe.inc" );

port = get_http_port( default: 8080 );

concl_url = "/index.htm";

buf = http_get_cache( port: port, item: concl_url );
model = "unknown";
version = "unknown";
mod = eregmatch( string: buf, pattern: 'Basic realm[ ]*=[ ]*"(WF[0-9]+[A-Z]*)_?[A-Z]*"', icase: TRUE );
if( ! isnull( mod[1] ) ) {
  model = mod[1];
}
else {
  post_data = make_array( 'mode_name', 'netcore_get', 'no', 'no' );
  concl_url = "/netcore_get.cgi";
  req = http_post_req( port: port, url: concl_url, data: post_data, accept_header: '*/*', host_header_use_ip: TRUE );
  res = http_keepalive_send_recv( port: port, data: req );
  mod = eregmatch( string: res, pattern: '"hw_version_mode"[ ]*[:][ ]*"(WF[0-9]+[A-Z]*)"', icase: TRUE );
  if( ! isnull( mod[1] ) ) {
    model = mod[1];
    ver = eregmatch( string: res, pattern: '"version"[ ]*[:][ ]*"[^"]*-V([0-9.]+)', icase: TRUE );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      set_kb_item( name: "netis/router/fw_version", value: version );
    }
  }
  else {
    exit( 0 );
  }
}

set_kb_item( name: "netis/router/detected", value: TRUE );
set_kb_item( name: "netis/router/model", value: tolower( model ) );

CPE += tolower( model ) + ":";

register_and_report_cpe( app: "Netis " + model,
                         ver: version,
                         concluded: mod[0],
                         base: CPE,
                         expr: '([0-9.]+)',
                         insloc: "/",
                         regPort: port,
                         conclUrl: concl_url );

exit( 0 );
