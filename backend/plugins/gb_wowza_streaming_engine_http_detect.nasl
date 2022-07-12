# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113661");
  script_version("2020-03-31T11:38:16+0000");
  script_tag(name:"last_modification", value:"2020-04-01 10:03:03 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-30 14:14:14 +0100 (Mon, 30 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wowza Streaming Engine Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("wowza_streaming_engine/banner");

  script_tag(name:"summary", value:"Checks whether Wowza Streaming Engine is present on
  the target system and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"https://www.wowza.com/products/streaming-engine");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );

port = get_http_port( default: 80 );

buf = get_http_banner( port: port );

if( buf =~ 'Server: *WowzaStreamingEngine' ) {
  set_kb_item( name: "wowza_streaming_engine/detected", value: TRUE );
  set_kb_item( name: "wowza_streaming_engine/http/detected", value: TRUE );
  set_kb_item( name: "wowza_streaming_engine/http/port", value: port );

  version = "unknown";

  ver = eregmatch( string: buf, pattern: 'WowzaStreamingEngine/([0-9.]+)' );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    set_kb_item( name: "wowza_streaming_engine/http/" + port + "/version", value: version );
    set_kb_item( name: "wowza_streaming_engine/http/" + port + "/concluded", value: ver[0] );
  }

}

exit( 0 );
