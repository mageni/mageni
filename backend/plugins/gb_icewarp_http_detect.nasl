###############################################################################
# OpenVAS Vulnerability Test
#
# IceWarp Web Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140329");
  script_version("2020-11-04T13:41:39+0000");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-08-28 14:59:29 +0700 (Mon, 28 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IceWarp Mail Server Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of IceWarp Mail Server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IceWarp/banner");

  script_xref(name:"URL", value:"http://www.icewarp.com/");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "port_service_func.inc" );

port = http_get_port( default: 80 );

if( ! banner = http_get_remote_headers( port: port ) )
  exit( 0 );

if( banner =~ 'IceWarp/' ) {
  replace_kb_item( name: "icewarp/mailserver/detected", value: TRUE );
  replace_kb_item( name: "icewarp/mailserver/http/detected", value: TRUE );
  set_kb_item( name: "icewarp/mailserver/http/port", value: port );

  version = "unknown";
  vers = eregmatch( pattern: "IceWarp/([0-9.]+)", string: banner, icase: TRUE );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name: "icewarp/mailserver/http/" + port + "/concluded", value: vers[0] );
  }
  set_kb_item( name: "icewarp/mailserver/http/" + port + "/version", value: version );
}

exit(0);
