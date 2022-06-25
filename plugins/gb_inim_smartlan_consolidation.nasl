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
  script_oid("1.3.6.1.4.1.25623.1.0.143256");
  script_version("2019-12-17T08:00:22+0000");
  script_tag(name:"last_modification", value:"2019-12-17 08:00:22 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-16 08:34:42 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Inim SmartLAN Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected Inim SmartLAN devices including the version numbe.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_inim_smartlan_http_detect.nasl", "gb_inim_smartlan_telnet_detect.nasl");
  script_mandatory_keys("inim/smartlan/detected");

  script_xref(name:"URL", value:"https://www.inim.biz/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("inim/smartlan/detected"))
  exit(0);

detected_version = "unknown";

foreach source (make_list("http")) {
  version_list = get_kb_list("inim/smartlan/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

app_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:inim:smartlan_g:");
if (!app_cpe)
  app_cpe = "cpe:/a:inim:smartlan_g";

location = "/";

if (http_ports = get_kb_list("inim/smartlan/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("inim/smartlan/http/" + port + "/concluded");
    concUrl = get_kb_item("inim/smartlan/http/" + port + "/concUrl");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: app_cpe, port: port, location: location, service: "www");
  }
}

if (telnet_ports = get_kb_list("inim/smartlan/telnet/port")) {
  foreach port (telnet_ports) {
    extra += "Telnet on port " + port + '/tcp\n';

    concluded = get_kb_item("inim/smartlan/telnet/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: app_cpe, port: port, location: location, service: "telnet");
  }
}

os_cpe = "cpe:/o:inim:smartlan_g_firmware";
register_and_report_os(os: "SmartLAN Firmware", version: detected_version, cpe: os_cpe, desc: "Inim SmartLAN Detection Consolidation",
                       runs_key: "unixoide");

report = build_detection_report(app: "Inim SmartLAN", version: detected_version, cpe: app_cpe, install: location);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

if (report)
  log_message(port: 0, data: report);

exit(0);
