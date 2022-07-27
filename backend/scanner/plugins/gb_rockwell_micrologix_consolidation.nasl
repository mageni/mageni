###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rockwell_micrologix_consolidation.nasl 12766 2018-12-12 08:34:25Z ckuersteiner $
#
# Rockwell Automation MicroLogix Detection Consolidation
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
  script_oid("1.3.6.1.4.1.25623.1.0.141772");
  script_version("$Revision: 12766 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-12 09:34:25 +0100 (Wed, 12 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-12 13:23:36 +0700 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rockwell Automation MicroLogix Detection Consolidation");

  script_tag(name:"summary", value:"Reports the Rockwell Automation MicroLogix model and firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_rockwell_micrologix_http_detect.nasl", "gb_rockwell_micrologix_ethernetip_detect.nasl");
  script_mandatory_keys("rockwell_micrologix/detected");

  script_xref(name:"URL", value:"http://ab.rockwellautomation.com/Programmable-Controllers/MicroLogix-Systems");;

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!get_kb_item("rockwell_micrologix/detected"))
  exit(0);

detected_model = "unknown";
detected_fw_version = "unknown";
detected_series = "";

foreach source (make_list("http", "ethernetip")) {
  fw_version_list = get_kb_list("rockwell_micrologix/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      set_kb_item(name: "rockwell_micrologix/fw_version", value: fw_version);
    }
  }

  model_list= get_kb_list("rockwell_micrologix/" + source + "/*/model");
  foreach model (model_list) {
    if (model && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "rockwell_micrologix/model", value: model);
    }
  }

  ser_list = get_kb_list("rockwell_micrologix/" + source + "/*/series");
  foreach series (ser_list) {
    if (series && detected_series == "") {
      detected_series = series;
      set_kb_item(name: "rockwell_micrologix/series", value: series);
    }
  }
}

app_name = "Rockwell Automation MicroLogix Controller ";
if (detected_model != "unknown") {
  app_name += detected_model;
  mod = eregmatch(pattern: '([^ ]+)', string: detected_model);
  app_cpe = 'cpe:/a:rockwellautomation:' + tolower(mod[1]);
  os_cpe = 'cpe:/o:rockwellautomation:' + tolower(mod[1]) + '_firmware';
  hw_cpe = 'cpe:/h:rockwellautomation:' + tolower(mod[1]);
}
else {
  app_cpe = 'cpe:/a:rockwellautomation:micrologix';
  os_cpe = 'cpe:/o:rockwellautomation:micrologix_firmware';
  hw_cpe = 'cpe:/h:rockwellautomation:micrologix';
}

if (detected_fw_version != "unknown") {
  app_cpe += ":" + detected_fw_version;
  os_cpe += ":" + detected_fw_version;
}

if (detected_series != "")
  app_name += " Series " + detected_series;

register_and_report_os(os: "Rockwell Automation MicroLogix Controller Firmware", cpe: os_cpe,
                       desc: "Rockwell Automation MicroLogix Detection Consolidation", runs_key: "unixoide");

location = "/";

if (http_ports = get_kb_list("rockwell_micrologix/http/port")) {
  foreach port (http_ports) {
    mac = get_kb_item("rockwell_micrologix/http/" + port + "/mac");
    if (mac)
      macaddr = 'MAC address:    ' + mac;

    extra += "HTTP(s) on port " + port + '/tcp\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: app_cpe, location: location, port: port, service: "www");
  }
}

if (ether_ports = get_kb_list("rockwell_micrologix/ethernetip/port")) {
  foreach port (ether_ports) {
    extra += 'EtherNet/IP on port ' + port + '/udp/tcp\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "ethernetip");
    register_product(cpe: os_cpe, location: location, port: port, service: "ethernetip");
    register_product(cpe: app_cpe, location: location, port: port, service: "ethernetip");
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
