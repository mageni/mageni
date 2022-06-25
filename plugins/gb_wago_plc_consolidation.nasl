###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wago_plc_consolidation.nasl 14032 2019-03-07 10:54:39Z cfischer $
#
# WAGO PLC Detection Consolidation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141766");
  script_version("$Revision: 14032 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:54:39 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-07 12:20:20 +0700 (Fri, 07 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WAGO PLC Detection Consolidation");

  script_tag(name:"summary", value:"Reports the WAGO PLC Controller model and firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_wago_plc_http_detect.nasl", "gb_wago_plc_snmp_detect.nasl",
                      "gb_wago_plc_ethernetip_detect.nasl");
  script_mandatory_keys("wago_plc/detected");

  script_xref(name:"URL", value:"https://www.wago.com/global/c/plcs-%E2%80%93-controllers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!get_kb_item("wago_plc/detected"))
  exit(0);

detected_model = "unknown";
detected_fw_version = "unknown";

foreach source (make_list("http", "ethernetip", "opcua", "snmp")) {
  fw_version_list = get_kb_list("wago_plc/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version && fw_version != "unknown") {
      if (detected_fw_version == "unknown") {
        detected_fw_version = fw_version;
        set_kb_item(name: "wago_plc/fw_version", value: fw_version);
      }
      # e.g. EtherNet/IP version is less accurate than http
      else if (version_is_greater(version: fw_version, test_version: detected_fw_version)) {
        detected_fw_version = fw_version;
        set_kb_item(name: "wago_plc/fw_version", value: fw_version);
      }
    }
  }

  model_list= get_kb_list("wago_plc/" + source + "/*/model");
  foreach model (model_list) {
    if (model && model != "unknown") {
      detected_model = model;
      set_kb_item(name: "wago_plc/model", value: model);
      break;
    }
  }
}

app_name = "WAGO PLC Controller ";
if (detected_model != "unknown") {
  app_name += detected_model;
  mod = eregmatch(pattern: '([0-9]+-[0-9]+)', string: detected_model);
  if (!isnull(mod[1])) {
    app_cpe = 'cpe:/a:wago:' + mod[1];
    os_cpe = 'cpe:/o:wago:' + mod[1] + '_firmware';
    hw_cpe = 'cpe:/h:wago:' + mod[1];
  } else {
    app_cpe = 'cpe:/a:wago:plc';
    os_cpe = 'cpe:/o:wago:plc_firmware';
    hw_cpe = 'cpe:/h:wago:plc';
  }
}
else {
  app_cpe = 'cpe:/a:wago:plc';
  os_cpe = 'cpe:/o:wago:plc_firmware';
  hw_cpe = 'cpe:/h:wago:plc';
}

if (detected_fw_version != "unknown") {
  app_cpe += ":" + detected_fw_version;
  os_cpe += ":" + detected_fw_version;
}

register_and_report_os(os: "WAGO PLC Controller Firmware", cpe: os_cpe, desc: "WAGO PLC Detection Consolidation",
                       runs_key: "unixoide");

location = "/";

if (http_ports = get_kb_list("wago_plc/http/port")) {
  foreach port (http_ports) {
    concluded = get_kb_item("wago_plc/http/" + port + "/concluded");
    concUrl = get_kb_item("wago_plc/http/" + port + "/concUrl");
    mac = get_kb_item("wago_plc/http/" + port + "/mac");
    if (mac)
      macaddr = 'MAC address:    ' + mac;

    extra += "HTTP(s) on port " + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';
    if (concUrl)
      extra += '  Concluded from version/product identification location:' + concUrl + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
    register_product( cpe:app_cpe, location:location, port:port, service:"www" );
  }
}

if (ether_ports = get_kb_list("wago_plc/ethernetip/port")) {
  foreach port (ether_ports) {
    extra += 'EtherNet/IP on port ' + port + '/udp/tcp\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"ethernetip" );
    register_product( cpe:os_cpe, location:location, port:port, service:"ethernetip" );
    register_product( cpe:app_cpe, location:location, port:port, service:"ethernetip" );
  }
}

if (opc_ports = get_kb_list("wago_plc/opcua/port")) {
  foreach port (opc_ports) {
    extra += 'OPC-UA on port ' + port + '/tcp\n';
    if (opc_version = get_kb_item("wago_plc/opcua/" + port + "/opc_version")) {
      extra += '  OPC-UA Version:  ' + opc_version + '\n';
      opc_cpe = "cpe:/a:wago/opcua_server:" + opc_version;
    }
    else
      opc_cpe = "cpe:/a:wago/opcua_server";

    if (build = get_kb_item("wago_plc/opcua/" + port + "/build"))
      extra += '  OPC-UA Build:    ' + build + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"opc-ua" );
    register_product( cpe:os_cpe, location:location, port:port, service:"opc-ua" );
    # nb: Register the app with the version of the opc server
    register_product( cpe:opc_cpe, location:location, port:port, service:"opc-ua" );
  }
}

if (snmp_ports = get_kb_list("wago_plc/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item('wago_plc/snmp/' + port + '/concluded');
    if (concluded)
      extra += '  Concluded from SNMP SysDesc: ' + concluded + '\n';

    register_product(cpe: app_cpe, location: port + '/udp', port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: port + '/udp', port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: port + '/udp', port: port, service: "snmp", proto: "udp");
  }
}

report += build_detection_report(app: app_name + " Firmware", version: detected_fw_version,
                                 install: "/", cpe: os_cpe);

report += '\n\n';
report += build_detection_report(app: app_name, version: detected_fw_version,
                                 install: "/", cpe: app_cpe);
report += '\n\n';
report += build_detection_report(app: app_name, install: "/", cpe: hw_cpe, skip_version: TRUE, extra: macaddr);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
