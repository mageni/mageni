# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143231");
  script_version("2019-12-06T09:54:56+0000");
  script_tag(name:"last_modification", value:"2019-12-06 09:54:56 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-06 06:51:25 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FreeSWITCH Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected FreeSWITCH installation including the version
  number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_freeswitch_sip_detect.nasl", "gb_freeswitch_http_detect.nasl",
                      "gb_freeswitch_mod_event_socket_service_detect.nasl");
  script_mandatory_keys("freeswitch/detected");

  script_xref(name:"URL", value:"https://freeswitch.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("freeswitch/detected"))
  exit(0);

detected_version = "unknown";

foreach source (make_list("sip", "http")) {
  version_list = get_kb_list("freeswitch/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:freeswitch:freeswitch:");
if (!cpe)
  cpe = "cpe:/a:freeswitch:freeswitch";

location = "/";

if (sip_ports = get_kb_list("freeswitch/sip/tcp/port")) {
  foreach port (sip_ports) {
    concluded = get_kb_item("freeswitch/sip/tcp/" + port + "/concluded");
    extra += "SIP on port " + port + '/tcp\n';
    extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "sip", proto: "tcp");
  }
}

if (sip_ports = get_kb_list("freeswitch/sip/udp/port")) {
  foreach port (sip_ports) {
    concluded = get_kb_item("freeswitch/sip/udp/" + port + "/concluded");
    extra += "SIP on port " + port + '/udp\n';
    extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "sip", proto: "udp");
  }
}

if (http_ports = get_kb_list("freeswitch/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';
    concluded = get_kb_item("freeswitch/http/" + port + "/concluded");
    concUrl = get_kb_item("freeswitch/http/" + port + "/concUrl");
    if (concluded) {
      extra +=  "  Concluded from version/product identification result: " + concluded + '\n';
      extra +=  "  Concluded from version/product identification location: " + concUrl + '\n';
    }

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (modevent_ports = get_kb_list("freeswitch/mod_event_socket/port")) {
  foreach port (modevent_ports) {
    extra += "mod_event_socket on port " + port + '/tcp\n';
  }
}

report = build_detection_report(app: "FreeSWITCH", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
