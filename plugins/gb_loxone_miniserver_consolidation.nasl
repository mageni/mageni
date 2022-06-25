# Copyright (C) 2021 Greenbone Networks GmbH
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

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145200");
  script_version("2021-01-21T15:27:51+0000");
  script_tag(name:"last_modification", value:"2021-01-22 11:28:48 +0000 (Fri, 22 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-20 06:52:37 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Loxone Miniserver Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Loxone Miniserver device detection.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_loxone_miniserver_http_detect.nasl");
  if (FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_loxone_miniserver_upnp_detect.nasl",
                        "gsf/gb_loxone_miniserver_knx_detect.nasl");
  script_mandatory_keys("loxone/miniserver/detected");

  script_xref(name:"URL", value:"https://www.loxone.com/enen/products/miniserver-extensions/");

  exit(0);
}

if (!get_kb_item("loxone/miniserver/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("http", "upnp", "knx")) {
  version_list = get_kb_list("loxone/miniserver/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:loxone:miniserver_firmware:");
if (!os_cpe)
  os_cpe = "cpe:/o:loxone:miniserver_firmware";

hw_cpe = "cpe:/h:loxone:miniserver";

register_and_report_os(os: "Loxone Miniserver Firmware", cpe: os_cpe, desc: "Loxone Miniserver Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("loxone/miniserver/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("loxone/miniserver/http/" + port + "/concluded");
    concUrl = get_kb_item("loxone/miniserver/http/" + port + "/concludedUrl");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (upnp_ports = get_kb_list("loxone/miniserver/upnp/port")) {
  foreach port (upnp_ports) {
    extra += 'UPNP on port ' + port + '/udp\n';

    concUrl = get_kb_item("loxone/miniserver/upnp/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "upnp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "upnp", proto: "udp");
  }
}

if (knx_ports = get_kb_list("loxone/miniserver/knx/port")) {
  foreach port (knx_ports) {
    extra += 'KNX on port ' + port + '/udp\n';

    concluded = get_kb_item("loxone/miniserver/knx/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "knx", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "knx", proto: "udp");
  }
}

report = build_detection_report(app: "Loxone Miniserver Firmware", version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: "Loxone Miniserver", skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
