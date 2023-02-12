# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142684");
  script_version("2023-02-03T10:10:17+0000");
  script_tag(name:"last_modification", value:"2023-02-03 10:10:17 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"creation_date", value:"2019-08-01 01:29:50 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Crestron AirMedia Presentation Gateway Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Crestron AirMedia Presentation Gateway
  detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_crestron_airmedia_snmp_detect.nasl", "gb_crestron_airmedia_http_detect.nasl",
                      "gb_crestron_cip_detect.nasl");
  script_mandatory_keys("crestron_airmedia/detected");

  script_xref(name:"URL", value:"https://www.crestron.com/en-US/Products/Featured-Solutions/Airmedia");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");

if (!get_kb_item("crestron_airmedia/detected"))
  exit(0);

detected_model = "unknown";
detected_fw    = "unknown";

foreach source (make_list("snmp", "cip")) {
  model_list = get_kb_list("crestron_airmedia/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "crestron_airmedia/model", value: detected_model);
      break;
    }
  }

  fw_list = get_kb_list("crestron_airmedia/" + source + "/*/fw_version");
  foreach fw (fw_list) {
    if (fw != "unknown" && detected_fw == "unknown") {
      detected_fw = fw;
      set_kb_item(name: "crestron_airmedia/firmware_version", value: detected_fw);
      break;
    }
  }
}

if (detected_model != "unknown") {

  # nb: For at least SNMP the AM-101 devices had reported themselves as AM-100 devices like e.g.:
  #
  # Crestron Electronics AM-100 (Version 2.8.0.32)
  #
  # But the first firmware version for AM-101 is/was 2.0.0.0, so we can differentiate that way and
  # "overwriting" a previous found / defined model here. This should be safe because AM-100 devices
  # are EOL and probably will never receive a 2.x firmware.
  if (detected_model == "AM-100" && detected_fw =~ "^2\.[0-9]+") {
    detected_model = "AM-101";
    special_note = '\n\nNote: AM-101 devices are reporting themselves as AM-100 devices which has been handled in this consolidation accordingly.';
  }

  os_name = "Crestron AirMedia Presentation Gateway " + detected_model + " Firmware";
  hw_name = "Crestron AirMedia Presentation Gateway " + detected_model;

  os_cpe = build_cpe(value: detected_fw, exp: "^([0-9.]+)", base: "cpe:/o:crestron:" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:crestron:" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:crestron:" + tolower(detected_model);
}
else {
  os_name = "Crestron AirMedia Presentation Gateway Unknown Model Firmware";
  hw_name = "Crestron AirMedia Presentation Gateway Unknown Model";

  os_cpe = build_cpe(value: detected_fw, exp: "^([0-9.]+)", base: "cpe:/o:crestron:airmedia_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:crestron:airmedia_firmware";

  hw_cpe = "cpe:/h:crestron:airmedia";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Crestron AirMedia Presentation Gateway Detection Consolidation", runs_key: "unixoide");

location = "/";

if (http_ports = get_kb_list("crestron_airmedia/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';
    concUrl = get_kb_item("crestron_airmedia/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from URL: ' + http_report_vuln_url(port: port, url: concUrl, url_only: TRUE) + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("crestron_airmedia/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';
    concluded = get_kb_item("crestron_airmedia/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP sysDescr OID: ' + concluded + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (cip_ports = get_kb_list("crestron_airmedia/cip/port")) {
  foreach port (cip_ports) {
    extra += 'CIP (Crestron Internet Protocol) on port ' + port + '/udp\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "crestron-cip", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "crestron-cip", proto: "udp");
  }
}

report  = build_detection_report(app: os_name, version: detected_fw, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

# nb: Some of the parts above might leave a trailing newline behind so just stripping it away
# before adding the next note to the report.
report = chomp(report);

if (special_note)
  report += special_note;

log_message(port: 0, data: report);

exit(0);
