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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143598");
  script_version("2020-03-16T08:21:45+0000");
  script_tag(name:"last_modification", value:"2020-03-17 10:20:57 +0000 (Tue, 17 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-16 04:59:40 +0000 (Mon, 16 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa MGate Detection Consolidation");

  script_tag(name:"summary", value:"Reports the Moxa MGate model and version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_moxa_mgate_web_detect.nasl", "gb_moxa_mgate_telnet_detect.nasl");
  script_mandatory_keys("moxa/mgate/detected");

  script_xref(name:"URL", value:"https://www.moxa.com");

  exit(0);
}

if (!get_kb_item("moxa/mgate/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("http", "telnet")) {
  version_list = get_kb_list("moxa/mgate/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("moxa/mgate/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  build_list = get_kb_list("moxa/mgate/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "moxa/mgate/build", value: detected_build);
      break;
    }
  }
}

os_name = "Moxa MGate ";
hw_name = os_name;
if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:moxa:" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:moxa:" + tolower(detected_model);
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:moxa:mgate_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:mgate_firmware";

  hw_cpe = "cpe:/h:moxa:mgate";
}

register_and_report_os(os: os_name, cpe: os_cpe, desc: "Moxa MGate Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("moxa/mgate/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("moxa/mgate/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (telnet_ports = get_kb_list("moxa/mgate/telnet/port")) {
  foreach port (telnet_ports) {
    extra += 'Telnet banner on port ' + port + '/tcp\n';

    concluded = get_kb_item("moxa/mgate/telnet/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe,
                                 extra: "Build: " + detected_build);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
