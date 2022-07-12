# Copyright (C) 2016 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106224");
  script_version("2020-03-31T11:38:16+0000");
  script_tag(name:"last_modification", value:"2020-04-01 10:03:03 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2016-09-07 11:27:17 +0700 (Wed, 07 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wowza Streaming Engine Detection (RTSP)");

  script_tag(name:"summary", value:"Detection of Wowza Streaming Engine

  The script attempts to identify Wowza Streaming Engine via RTSP banner to extract the version number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  script_mandatory_keys("RTSP/server_banner/available");

  script_xref(name:"URL", value:"https://www.wowza.com/products/streaming-engine");

  exit(0);
}

include( "host_details.inc" );
include( "misc_func.inc" );

port = get_port_for_service( default: 554, proto: "rtsp" );

if( ! banner = get_kb_item( "RTSP/" + port + "/server_banner" ) )
  exit( 0 );

if( banner =~ "Server: *Wowza Streaming Engine" ) {
  set_kb_item( name: "wowza_streaming_engine/detected", value: TRUE );
  set_kb_item( name: "wowza_streaming_engine/rtsp/detected", value: TRUE );
  set_kb_item( name: "wowza_streaming_engine/rtsp/port", value: port );

  version = "unknown";
  build = "unknown";

  ver = eregmatch( pattern: "Wowza Streaming Engine ([0-9.]+)", string: banner );

  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    set_kb_item( name: "wowza_streaming_engine/rtsp/" + port + "/version", value: version );
    set_kb_item( name: "wowza_streaming_engine/rtsp/" + port + "/concluded", value: ver[0] );
  }

}

exit( 0 );
