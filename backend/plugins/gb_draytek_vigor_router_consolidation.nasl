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
  script_oid("1.3.6.1.4.1.25623.1.0.143663");
  script_version("2020-04-01T08:29:54+0000");
  script_tag(name:"last_modification", value:"2020-04-01 10:03:03 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-31 09:10:05 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DrayTek Vigor Router Detection Consolidation");

  script_tag(name:"summary", value:"Reports the DrayTek Vigor Router model and version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_draytek_vigor_router_http_detect.nasl", "gb_draytek_vigor_router_snmp_detect.nasl");
  script_mandatory_keys("draytek/vigor/router/detected");

  script_xref(name:"URL", value:"https://www.draytek.com/products/routers/");

  exit(0);
}

if (!get_kb_item("draytek/vigor/router/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_model = "unknown";
detected_version = "unknown";
os_name = "DrayTek Vigor ";
hw_name = os_name;
location = "/";

foreach source (make_list("snmp", "http")) {
  model_list = get_kb_list("draytek/vigor/router/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  version_list = get_kb_list("draytek/vigor/router/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;

  os_cpe = build_cpe(value: tolower(detected_version), exp: "^([a-z0-9._]+)",
                     base: "cpe:/o:draytek:vigor" + tolower(model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:draytek:vigor" + tolower(model) + "_firmware";

  hw_cpe = "cpe:/h:draytek:vigor" + tolower(model);
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";

  os_cpe = build_cpe(value: tolower(detected_version), exp: "^([a-z0-9._]+)", base: "cpe:/o:draytek:vigor_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:draytek:vigor_firmware";

  hw_cpe = "cpe:/h:draytek:vigor";
}

register_and_report_os(os: os_name, cpe: os_cpe, desc: "DrayTek Vigor Router Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("draytek/vigor/router/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';
    concluded = get_kb_item("draytek/vigor/router/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    concUrl = get_kb_item("draytek/vigor/router/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += "  Concluded from version/product identification location: " + concUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("draytek/vigor/router/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';
    concluded = get_kb_item("draytek/vigor/router/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP Banner: ' + concluded + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
