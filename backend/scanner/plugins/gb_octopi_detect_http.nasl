###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_octopi_detect_http.nasl 11881 2018-10-12 13:02:51Z mmartin $
#
# OctoPi Version Detection (HTTP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107343");
  script_version("$Revision: 11881 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:02:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-11 16:21:34 +0200 (Thu, 11 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OctoPi Version Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of OctoPi Raspberry Pi distribution for 3D printers using HTTP.");

  script_xref(name:"URL", value:"https://octoprint.org/download/");

  exit(0);
}
include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

banner_type = "HTTP WWW-Authenticate banner / HTTP Interface";
SCRIPT_DESC = "OctoPi Version Detection (HTTP)";

port = get_http_port( default: 80 );
banner = get_http_banner( port:port );
buf = http_get_cache(item:"/", port:port);

# Basic realm="Octopi Interface"
# Basic realm="OctoPi"
if( banner =~ '^WWW-Authenticate: Basic realm="OctoPi (Interface)?"' )
  octopi_auth_found = TRUE;

if( octopi_auth_found || ( "OctoPrint</title>" >< buf && "plugin_octopi_support_version" >< buf ) ) {

  install = "/";
  conclUrl = report_vuln_url(port: port, url: "/", url_only: TRUE);
  version = 'unknown';

  if( octopi_auth_found ) {
    set_kb_item( name: "octopi/http/ " + port + "/auth", value:TRUE);
    set_kb_item( name: "octopi/http/auth", value:TRUE);
  } else {
    set_kb_item( name: "octopi/http/ " + port + "/noauth", value:TRUE);
    set_kb_item( name: "octopi/http/noauth", value:TRUE);
  }

  set_kb_item( name: "octopi/detected", value: TRUE );
  set_kb_item( name: "octopi/http/detected", value: TRUE );
  set_kb_item( name: "octopi/http/port", value: port );

  vers = eregmatch( pattern:'<span class="plugin_octopi_support_version">([0-9.]+)</span>',
  string:buf, icase:TRUE );
    if( vers[1] ) {
      version = vers[1];
      set_kb_item( name: "octopi/http/" + port + "/version", value:version );
      set_kb_item( name: "octopi/http/" + port + "/concluded", value:vers[0] );
      set_kb_item( name: "octopi/http/" + port + "/concludedUrl", value:conclUrl );
    }

  # For later use in "consolidation" VT:
  register_and_report_os( os:"OctoPi Raspberry Pi distribution", version:vers[1], cpe:"cpe:/o:octoprint:octopi", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

exit(0);
