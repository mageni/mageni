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
  script_oid("1.3.6.1.4.1.25623.1.0.113662");
  script_version("2020-03-31T11:38:16+0000");
  script_tag(name:"last_modification", value:"2020-04-01 10:03:03 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-30 14:56:55 +0100 (Mon, 30 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wowza Streaming Engine Detection (Consolidation)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_wowza_streaming_engine_http_detect.nasl", "gb_wowza_streaming_engine_rtsp_detect.nasl");
  script_mandatory_keys("wowza_streaming_engine/detected");

  script_tag(name:"summary", value:"Checks whether Wowza Streaming Engine
  is present on the target system.");

  script_xref(name:"URL", value:"https://www.wowza.com/products/streaming-engine");

  exit(0);
}

CPE = "cpe:/a:wowza:streaming_engine:";

include( "host_details.inc" );
include( "cpe.inc" );

version = "unknown";
concluded = "";
extra = 'Concluded from the following protocols:';

foreach proto ( make_list( "rtsp", "http" ) ) {
  if( ! ports = get_kb_list( "wowza_streaming_engine/" + proto + "/port" ) )
    continue;
  foreach port( ports ) {
    vers = get_kb_item( "wowza_streaming_engine/" + proto + "/" + port + "/version" );
    concl = get_kb_item( "wowza_streaming_engine/" + proto + "/" + port + "/concluded" );
    if( ! isnull( vers ) && version == "unknown" )
      version = vers;
    if( concluded == "" )
      concluded = toupper( proto );
    else if( toupper( proto ) >!< concluded )
      concluded += ", " + toupper( proto );
    if( ! isnull( concl ) ) {
      extra += '\n\n' + port + "/" + toupper( proto ) + ":";
      extra += '\n    ' + concl;
    }

    if( proto == "http" )
      service = "www";
    else
      service = proto;

    cpe = build_cpe( value: vers, exp: '([0-9.]+)', base: CPE );
    register_product( cpe: cpe, location: port + "/tcp", port: port, service: service );
  }
}

report = build_detection_report( app: "Wowza Streaming Engine",
                                 version: version,
                                 cpe: CPE,
                                 concluded: concluded,
                                 extra: extra );

log_message( port: 0, data: report );

exit( 0 );
