###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wowza_streaming_engine_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Wowza Streaming Engine Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106224");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-07 11:27:17 +0700 (Wed, 07 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wowza Streaming Engine Detection");

  script_tag(name:"summary", value:"Detection of Wowza Streaming Engine

The script attempts to identify Wowza Streaming Engine via RSTP banner to extract the version number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);

  script_xref(name:"URL", value:"https://www.wowza.com/products/streaming-engine");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!port = get_kb_item("Services/rtsp"))
  port = 554;

if (!banner = get_kb_item(string("RTSP/", port, "/Server")))
  exit(0);

if ("Server: Wowza Streaming Engine" >< banner) {
  version = "unknown";
  build = "unknown";

  ver = eregmatch(pattern: "Wowza Streaming Engine ([0-9.]+)( build([0-9]+))?", string: banner);

  if (!isnull(ver[1])) {
    version = ver[1];
    set_kb_item(name: "wowza_streaming_engine/version", value: version);
  }

  if (!isnull(ver[3])) {
    build = ver[3];
    set_kb_item(name: "wowza_streaming_engine/build", value: build);
  }

  set_kb_item(name: "wowza_streaming_engine/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:wowza:streaming_engine:");
  if (!cpe)
    cpe = "cpe:/a:wowza:streaming_engine:";

  register_product(cpe: cpe, location: "rtsp", port: port);

  log_message(data: build_detection_report(app: "Wowza Streaming Engine", version: version + " Build: " + build,
                                           install: "rtsp", cpe: cpe, concluded: ver[0]),
              port: port);
  exit(0);
}

exit(0);
