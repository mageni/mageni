###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_wnap_consolidation.nasl 12575 2018-11-29 10:41:31Z ckuersteiner $
#
# NETGEAR WNAP/WNDAP Device Detection Consolidation
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141740");
  script_version("$Revision: 12575 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-29 11:41:31 +0100 (Thu, 29 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-29 16:18:35 +0700 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NETGEAR WNAP/WNDAP Device Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected NETGEAR WNAP/WNDAP device including the version
number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_netgear_wnap_snmp_detect.nasl", "gb_netgear_wnap_http_detect.nasl");
  script_mandatory_keys("netgear_wnap/detected");

  exit(0);
}

include("host_details.inc");

if (!get_kb_item("netgear_wnap/detected"))
  exit(0);

detected_model = "unknown";
detected_fw_version = "unknown";

foreach source (make_list("snmp", "http")) {
  model_list = get_kb_list("netgear_wnap/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "netgear_wnap/model", value: model);
    }
  }

  fw_version_list = get_kb_list("netgear_wnap/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version != "unknown" && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      set_kb_item(name: "netgear_wnap/fw_version", value: fw_version);
    }
  }
}

if (detected_model != "unknown") {
  hw_cpe = "cpe:/h:netgear:" + tolower(detected_model);
  os_cpe = "cpe:/o:netgear:" + tolower(detected_model);
} else {
  hw_cpe = "cpe:/h:netgear:unknown_model";
  os_cpe = "cpe:/o:netgear:wnap_firmware";
}

location = "/";

if (detected_fw_version != "unknown")
  os_cpe += ":" + detected_fw_version;

if (snmp_ports = get_kb_list("netgear_wnap/snmp/port")) {
  foreach port (snmp_ports) {
    concluded = get_kb_item("netgear_wnap/snmp/" + port + "/concluded");
    extra += "SNMP on port " + port + '/udp\n';
    if (concluded)
      extra += '  Concluded from SNMP SysDesc: ' + concluded + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (http_ports = get_kb_list("netgear_wnap/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "www");
  }
}

report = build_detection_report(app: "NETGEAR " + detected_model + " Firmware", version: detected_fw_version,
                                install:location, cpe:os_cpe );
report += '\n\n';
report += build_detection_report(app: "NETGEAR " + detected_model + " Device", install: location, cpe: hw_cpe,
                                 skip_version: TRUE);
if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
