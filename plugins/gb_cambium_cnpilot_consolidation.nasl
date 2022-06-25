###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cambium_cnpilot_consolidation.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# Cambium Networks cnPilot Detection Consolidation
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140631");
  script_version("$Revision: 10901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-12-22 16:10:50 +0700 (Fri, 22 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks cnPilot Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected Cambium Networks cnPilot including the
version number and exposed services.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_cambium_cnpilot_http_detect.nasl", "gb_cambium_cnpilot_snmp_detect.nasl");
  script_mandatory_keys("cambium_cnpilot/detected");

  script_xref(name:"URL", value:"https://www.cambiumnetworks.com/products/wifi/");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "cambium_cnpilot/detected" ) ) exit( 0 );

detected_fw_version = "unknown";
detected_model = "unknown";

foreach source (make_list("http", "snmp")) {
  fw_version_list = get_kb_list("cambium_cnpilot/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      set_kb_item(name: "cambium_cnpilot/fw_version", value: fw_version);
    }
  }

  model_list = get_kb_list("cambium_cnpilot/" + source + "/*/model");
  foreach model (model_list) {
    if (model && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cambium_cnpilot/model", value: model);
    }
  }
}

app_name = "Cambium Networks cnPilot";

if (detected_model != "unknown")
  app_name += " " + detected_model;

if (detected_fw_version != "unknown")
  cpe = "cpe:/a:cambium:cnpilot:" + tolower(detected_fw_version);
else
  cpe = 'cpe:/a:cambium:cnpilot';

if (http_ports = get_kb_list("cambium_cnpilot/http/port")) {
  foreach port (http_ports) {
    concluded = get_kb_item("cambium_cnpilot/http/" + port + "/concluded");
    extra += "HTTP(s) on port " + port + '/tcp\n';
    if (concluded) {
      extra += 'Concluded from: ' + concluded + '\n';
    }
    register_product(cpe: cpe, location: "/", port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("cambium_cnpilot/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';
    register_product(cpe: cpe, location: port + '/udp', port: port, service: "snmp", proto: "udp");
  }
}

report = build_detection_report(app: app_name, version: detected_fw_version, install: "/", cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
