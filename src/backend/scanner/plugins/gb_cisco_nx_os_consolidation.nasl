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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105690");
  script_version("2022-12-12T08:47:36+0000");
  script_tag(name:"last_modification", value:"2022-12-12 08:47:36 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"creation_date", value:"2016-05-12 12:21:43 +0200 (Thu, 12 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco NX-OS Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_cisco_nx_os_snmp_detect.nasl",
                      "gb_cisco_nx_os_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cisco_nx_os_ssh_detect.nasl",
                        "gsf/gb_cisco_nx_os_telnet_detect.nasl");
  script_mandatory_keys("cisco/nx_os/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco NX-OS detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/ios-nx-os-software/nx-os/index.html");

  exit(0);
}

if (!get_kb_item("cisco/nx_os/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_device = "unknown";
detected_model = "unknown";
location = "/";
os_name = "Cisco NX-OS";

foreach source (make_list("ssh-login", "snmp", "ssh", "telnet")) {
  device_list = get_kb_list("cisco/nx_os/" + source + "/*/device");
  foreach device (device_list) {
    if (device != "unknown" && detected_device == "unknown") {
      detected_device = device;
      set_kb_item(name: "cisco/nx_os/device", value: detected_device);
      break;
    }
  }

  model_list = get_kb_list("cisco/nx_os/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cisco/nx_os/model", value: detected_model);
      break;
    }
  }

  version_list = get_kb_list("cisco/nx_os/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_cpe = build_cpe(value: detected_version, exp: "^([0-9a-zA-Z.\(\)]+)", base: "cpe:/o:cisco:nx-os:");
if (!os_cpe)
  os_cpe = "cpe:/o:cisco:nx-os";

if (detected_model != "unknown") {
  if (detected_device != "unknown") {
    hw_name = "Cisco " + detected_device + " " + detected_model;
    if (detected_model =~ "^[0-9]")
      hw_cpe = "cpe:/h:cisco:" + tolower(detected_device) + "_" + tolower(detected_model);
    else
      hw_cpe = "cpe:/h:cisco:" + tolower(detected_model);
  } else {
    hw_name = "Cisco " + detected_model;
    hw_cpe = "cpe:/h:cisco:" + tolower(detected_model);
  }
} else {
  if (detected_device != "unknown")
    hw_name = "Cisco " + detected_device + " Switch";
  else
    hw_name = "Cisco Switch Unknown Model";

  hw_cpe = "cpe:/h:cisco:switch";
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Cisco NX-OS Detection Consolidation");

if (ssh_login_ports = get_kb_list("cisco/nx_os/ssh-login/port")) {
  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    extra += "  Port: " + port + '/tcp\n';

    concluded = get_kb_item("cisco/nx_os/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded;

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

if (ssh_ports = get_kb_list("cisco/nx_os/ssh/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over SSH:\n';

  foreach port (ssh_ports) {
    extra += "  Port:                        " + port + '/tcp\n';
    concluded = get_kb_item("cisco/nx_os/ssh/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from SSH banner:   " + concluded;

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh");
  }
}

if (telnet_ports = get_kb_list("cisco/nx_os/telnet/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over Telnet:\n';

  foreach port (telnet_ports) {
    extra += "  Port:                          " + port + '/tcp\n';
    concluded = get_kb_item("cisco/nx_os/telnet/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from Telnet banner:  " + concluded;

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

if (snmp_ports = get_kb_list("cisco/nx_os/snmp/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over SNMP:\n';

  foreach port (snmp_ports) {
    extra += "  Port:                        " + port + '/udp\n';

    concludedMod = get_kb_item("cisco/nx_os/snmp/" + port + "/concludedModel");
    concludedModOID = get_kb_item("cisco/nx_os/snmp/" + port + "/concludedModelOID");
    if (concludedMod && concludedModOID)
      extra += '  Concluded model from:        "' + concludedMod + '" via OID: "' + concludedModOID + '"\n';

    concluded = get_kb_item("cisco/nx_os/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from sysDescr OID: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
