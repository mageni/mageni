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
  script_oid("1.3.6.1.4.1.25623.1.0.112731");
  script_version("2020-04-09T09:18:10+0000");
  script_tag(name:"last_modification", value:"2020-04-09 11:12:54 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-01-15 02:15:18 +0000 (Wed, 15 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei VRP Detection Consolidation");

  script_tag(name:"summary", value:"Consolidates the Huawei Versatile Routing Platform (VRP) network devices detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_huawei_vrp_network_device_snmp_detect.nasl", "gb_huawei_vrp_network_device_ssh_detect.nasl",
                      "gb_huawei_vrp_network_device_http_detect.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_xref(name:"URL", value:"http://e.huawei.com/en/products/enterprise-networking/switches");

  exit(0);
}

if (!get_kb_item("huawei/vrp/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
detected_model   = "Unknown Model";
detected_patch   = "unknown";

foreach source (make_list("ssh-login", "snmp", "http")) {
  version_list = get_kb_list("huawei/vrp/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      set_kb_item(name: "huawei/vrp/version", value: version);
      break;
    }
  }

  model_list = get_kb_list("huawei/vrp/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "Unknown Model") {
      detected_model = model;
      set_kb_item(name: "huawei/vrp/model", value: model);
      break;
    }
  }

  if (detected_version != "unknown" && detected_model != "Unknown Model")
    break;
}

os_name = "Huawei " + detected_model + " Versatile Routing Platform (VRP) network device Firmware";
hw_name = "Huawei " + detected_model + " Versatile Routing Platform (VRP) network device";

hw_cpe = "cpe:/h:huawei:" + tolower(detected_model);
hw_cpe = str_replace(string: hw_cpe, find: " ", replace: "_");

os_cpe = build_cpe(value: tolower(detected_version), exp: "^(v[0-9a-z]+)", base: "cpe:/o:huawei:" + tolower(detected_model) + "_firmware:");
if (!os_cpe)
  os_cpe = "cpe:/o:huawei:" + tolower(detected_model) + "_firmware";
os_cpe = str_replace(string: os_cpe, find: " ", replace: "_");

register_and_report_os(os: os_name, cpe: os_cpe, desc: "Huawei Switch Detection Consolidation", runs_key: "unixoide");

location = "/";
extra = ""; # nb: To make openvas-nasl-lint happy...

if (ssh_ports = get_kb_list("huawei/vrp/ssh-login/port")) {

  foreach port (ssh_ports) {
    if (extra)
      extra += '\n\n';
    extra += "SSH on port " + port + "/tcp";

    concluded = get_kb_item("huawei/vrp/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '\n  Concluded from version/product identification result:' + concluded;

    concluded_command = get_kb_item("huawei/vrp/ssh-login/" + port + "/concluded_command");
    if (concluded_command)
      extra += '\n  Concluded from version/product identification command(s): ' + concluded_command;

    patch_version = get_kb_item("huawei/vrp/ssh-login/" + port + "/patch");
    if (patch_version) {
      detected_patch = patch_version;

      if (detected_patch != "No patch installed")
        set_kb_item(name: "huawei/vrp/patch", value: detected_patch);
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

if (snmp_ports = get_kb_list("huawei/vrp/snmp/port")) {

  foreach port (snmp_ports) {
    if (extra)
      extra += '\n\n';
    extra += "SNMP on port " + port + "/udp";

    concluded = get_kb_item("huawei/vrp/snmp/" + port + "/concluded");
    if (concluded )
      extra += '\n  Concluded from: ' + concluded;

    patch_version = get_kb_item("huawei/vrp/snmp/" + port + "/patch");
    if (patch_version) {
      detected_patch = patch_version;

      if (detected_patch != "No patch installed")
        set_kb_item(name: "huawei/vrp/patch", value: detected_patch);
    }

    register_product(cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
  }
}

if (http_ports = get_kb_list("huawei/vrp/http/port")) {

  foreach port (http_ports) {
    if (extra)
      extra += '\n\n';
    extra += "HTTP(s) on port " + port + "/tcp";

    concluded = get_kb_item("huawei/vrp/http/" + port + "/concluded");
    if (concluded)
      extra += '\n  Concluded from version/product identification result: ' + concluded;

    concluded_location = get_kb_item("huawei/vrp/http/" + port + "/concluded_location");
    if (concluded_location)
      extra += '\n  Concluded from version/product identification location: ' + concluded_location;

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

report = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe,
                                extra: "Patch Version: " + detected_patch);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
