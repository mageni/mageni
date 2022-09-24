# Copyright (C) 2016 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105532");
  script_version("2022-09-21T08:38:59+0000");
  script_tag(name:"last_modification", value:"2022-09-21 08:38:59 +0000 (Wed, 21 Sep 2022)");
  script_tag(name:"creation_date", value:"2016-01-27 10:46:32 +0100 (Wed, 27 Jan 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco IOS XR Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_cisco_ios_xr_snmp_detect.nasl",
                      "gb_cisco_ios_xr_ssh_login_detect.nasl");
  script_mandatory_keys("cisco/ios_xr/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco IOS XR detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xr-software/index.html");

  exit(0);
}

if (!get_kb_item("cisco/ios_xr/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";
os_name = "Cisco IOS XR";

foreach source (make_list("ssh-login", "snmp")) {
  model_list = get_kb_list("cisco/ios_xr/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = str_replace(string: model, find: " Series");
      set_kb_item(name: "cisco/ios_xr/model", value: detected_model);
      break;
    }
  }

  version_list = get_kb_list("cisco/ios_xr/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:ios_xr:");
if (!os_cpe)
  cpe = "cpe:/o:cisco:ios_xr";

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Cisco IOS XR Detection Consolidation",
                       runs_key: "unixoide");

if (detected_model != "unknown") {
  os_name += " on " + detected_model;
  hw_cpe = "cpe:/h:cisco:" + str_replace(string: tolower(detected_model), find: " ", replace: "_");
}

if (snmp_ports = get_kb_list("cisco/ios_xr/snmp/port")) {
  extra += 'Remote Detection over SNMP:\n';

  foreach port (snmp_ports) {
    extra += '  Port:         ' + port + '/udp\n';

    concluded = get_kb_item("cisco/ios_xr/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP Banner:  ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_login_ports = get_kb_list("cisco/ios_xr/ssh-login/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    extra += '  Port:         ' + port + '/tcp\n';

    concluded = get_kb_item("cisco/ios_xr/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded;

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
if (hw_cpe) {
  report += '\n\n';
  report += build_detection_report(app: "Cisco " + detected_model, skip_version: TRUE, install: location,
                                   cpe: hw_cpe);
}

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
