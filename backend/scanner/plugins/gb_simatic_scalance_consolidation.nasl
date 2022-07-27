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
  script_oid("1.3.6.1.4.1.25623.1.0.145830");
  script_version("2021-04-28T11:39:57+0000");
  script_tag(name:"last_modification", value:"2021-04-29 10:46:31 +0000 (Thu, 29 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-27 04:18:09 +0000 (Tue, 27 Apr 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC SCALANCE Device Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Siemens SIMATIC SCALANCE device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_simatic_scalance_snmp_detect.nasl", "gb_simatic_scalance_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_simatic_scalance_telnet_detect.nasl");
  script_mandatory_keys("siemens/simatic/scalance/detected");

  script_xref(name:"URL", value:"https://new.siemens.com/global/en/products/automation/industrial-communication/scalance.html");

  exit(0);
}

if (!get_kb_item("siemens/simatic/scalance/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_fw_version = "unknown";
detected_hw_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source (make_list("snmp", "telnet", "http")) {
  version_list = get_kb_list("siemens/simatic/scalance/" + source + "/*/fw_version");
  foreach fw_version (version_list) {
    if (fw_version != "unknown" && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      break;
    }
  }

  model_list = get_kb_list("siemens/simatic/scalance/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  hw_version_list = get_kb_list("siemens/simatic/scalance/" + source + "/*/hw_version");
  foreach hw_version (hw_version_list) {
    if (hw_version != "unknown" && detected_hw_version == "unknown") {
      detected_hw_version = hw_version;
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = "Siemens SIMATIC SCALANCE " + detected_model + " Firmware";
  hw_name = "Siemens SIMATIC SCALANCE " + detected_model;

  cpe_model = tolower(ereg_replace(pattern: " ", string: detected_model, replace: "_"));

  os_cpe = build_cpe(value: detected_fw_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:siemens:scalance_" + cpe_model + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:siemens:scalance_" + cpe_model + "_firmware";

  hw_cpe = build_cpe(value: detected_hw_version, exp: "^([0-9.]+)",
                     base: "cpe:/h:siemens:scalance_" + cpe_model + ":");
  if (!hw_cpe)
    hw_cpe = "cpe:/h:siemens:scalance_" + cpe_model;
} else {
  os_name = "Siemens SIMATIC SCALANCE Unknown Model Firmware";
  hw_name = "Siemens SIMATIC SCALANCE Unknown Model";

  os_cpe = build_cpe(value: detected_fw_version, exp: "^([0-9.]+)", base: "cpe:/o:siemens:scalance_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:siemens:scalance_firmware";

  hw_cpe = build_cpe(value: detected_hw_version, exp: "^([0-9.]+)", base: "cpe:/h:siemens:scalance:");
  if (!hw_cpe)
    hw_cpe = "cpe:/h:siemens:scalance";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Siemens SIMATIC SCALANCE Device Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("siemens/simatic/scalance/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("siemens/simatic/scalance/http/" + port + "/concluded");
    concUrl = get_kb_item("siemens/simatic/scalance/http/" + port + "/concludedUrl");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("siemens/simatic/scalance/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item("siemens/simatic/scalance/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP Banner: ' + concluded + '\n';

    module =  get_kb_item("siemens/simatic/scalance/snmp/" + port + "/module");
    if (module) {
      extra += '  Module:      ' + module + '\n';
      set_kb_item(name: "siemens/simatic/scalance/module", value: module);
    }

    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (telnet_ports = get_kb_list("siemens/simatic/scalance/telnet/port")) {
  foreach port (telnet_ports) {
    extra += 'Telnet on port ' + port + '/tcp\n';

    concluded = get_kb_item("siemens/simatic/scalance/telnet/" + port + "/concluded");
    if (concluded)
      extra += '  Telnet Banner: ' + concluded + '\n';
  }

  register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
}

report  = build_detection_report(app: os_name, version: detected_fw_version, install: "/", cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, version: detected_hw_version, install: "/", cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
