# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.144526");
  script_version("2020-09-08T07:35:48+0000");
  script_tag(name:"last_modification", value:"2020-09-09 09:59:16 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-03 06:29:02 +0000 (Thu, 03 Sep 2020)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Linksys Devices Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Linksys device detections.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_linksys_devices_http_detect.nasl", "gb_linksys_devices_hnap_detect.nasl",
                      "gb_linksys_devices_snmp_detect.nasl", "gb_linksys_devices_ftp_detect.nasl");
  script_require_ports("linksys/detected");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("linksys/detected"))
  exit(0);

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source (make_list("http", "hnap", "snmp", "ftp")) {
  version_list = get_kb_list("linksys/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("linksys/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "linksys/model", value: detected_model);
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = "Linksys " + detected_model + " Firmware";
  hw_name = "linksys " + detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:linksys:" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:linksys:" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:linksys:" + tolower(detected_model);
} else {
  os_name = "Linksys Unknown Model Firmware";
  hw_name = "Linksys Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:linksys:device_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:linksys:device_firmware";

  hw_cpe = "cpe:/h:linksys:device";
}

register_and_report_os(os: os_name, cpe: os_cpe, desc: "Linksys Devices Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("linksys/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("linksys/http/" + port + "/concluded");
    concUrl = get_kb_item("linksys/http/" + port + "/concludedUrl");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (hnap_ports = get_kb_list("linksys/hnap/port")) {
  foreach port (hnap_ports) {
    extra += 'HNAP on port ' + port + '/tcp\n';

    concluded = get_kb_item("linksys/hnap/" + port + "/concluded");
    concUrl = get_kb_item("linksys/hnap/" + port + "/concludedUrl");

    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("linksys/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item("linksys/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP Banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ftp_ports = get_kb_list("linksys/ftp/port")) {
  foreach port (ftp_ports) {
    extra += 'FTP on port ' + port + '/tcp\n';

    concluded = get_kb_item("linksys/ftp/" + port + "/concluded");
    if (concluded)
      extra += '  FTP Banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ftp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ftp");
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
