# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.143102");
  script_version("2019-11-08T02:45:39+0000");
  script_tag(name:"last_modification", value:"2019-11-08 02:45:39 +0000 (Fri, 08 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-07 07:54:09 +0000 (Thu, 07 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LIVE555 Streaming Media Server Consolidation");

  script_tag(name:"summary", value:"The script reports the detected LIVE555 Streaming Media Server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_live555_http_detect.nasl", "gb_live555_detect.nasl");
  script_mandatory_keys("live555/streaming_media/detected");

  script_xref(name:"URL", value:"http://www.live555.com/mediaServer/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("live555/streaming_media/detected"))
  exit(0);

detected_version = "unknown";

foreach source (make_list("http", "rtsp")) {
  if (detected_version != "unknown")
    break;

  version_list = get_kb_list("live555/streaming_media/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:live555:streaming_media:");
if (!cpe)
  cpe = "cpe:/a:live555:streaming_media";

location = "/";

if (http_ports = get_kb_list("live555/streaming_media/http/port")) {
  foreach port (http_ports) {
    concluded = get_kb_item("live555/streaming_media/http/" + port + "/concluded");
    extra += "HTTP(s) on port " + port + '/tcp\n';
    if (concluded)
      extra += "  Concluded from: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (rtsp_ports = get_kb_list("live555/streaming_media/rtsp/port")) {
  foreach port (rtsp_ports) {
    concluded = get_kb_item("live555/streaming_media/rtsp/" + port + "/concluded");
    extra += "RTSP on port " + port + '/tcp\n';
    if (concluded)
      extra += "  Concluded from banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "rtsp");
  }
}

report = build_detection_report(app: "LIVE555 Streaming Media Server", version: detected_version, install: location,
                                cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
