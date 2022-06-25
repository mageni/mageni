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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146406");
  script_version("2021-08-02T08:21:20+0000");
  script_tag(name:"last_modification", value:"2021-08-04 10:51:24 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-30 07:59:39 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Epson Printer Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Epson Printer device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_epson_printer_http_detect.nasl", "gb_epson_printer_snmp_detect.nasl",
                      "gb_epson_printer_pjl_detect.nasl", "gb_epson_printer_ftp_detect.nasl",
                      "global_settings.nasl");
  script_mandatory_keys("epson/printer/detected");

  script_xref(name:"URL", value:"https://epson.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("epson/printer/detected"))
  exit(0);

detected_model = "unknown";
detected_fw_version = "unknown";
location = "/";

foreach source (make_list("http", "snmp", "hp-pjl", "ftp")) {
  model_list = get_kb_list("epson/printer/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "epson/printer/model", value: model);
      break;
    }
  }

  fw_version_list = get_kb_list("epson/printer/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version != "unknown" && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      break;
    }
  }
}

os_name = "Epson Printer ";
hw_name = os_name;

if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;
  cpe_model = tolower(detected_model);

  if (detected_fw_version != "unknown")
    os_cpe = build_cpe(value: tolower(detected_fw_version), exp: "^([0-9a-z.]+)",
                       base: "cpe:/o:epson:" + cpe_model + "_firmware:");
  else
    os_cpe = "cpe:/o:epson:" + cpe_model + "_firmware";

  hw_cpe = "cpe:/h:epson:" + cpe_model;
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";

  if (detected_fw_version != "unknown")
    os_cpe = build_cpe(value: tolower(detected_fw_version), exp: "^([0-9a-z.]+)",
                       base: "cpe:/o:epson:printer_firmware:");
  else
    os_cpe = "cpe:/o:epson:printer_firmware";

  hw_cpe = "cpe:/h:epson:printer";
}

if (http_ports = get_kb_list("epson/printer/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    modConcluded = get_kb_item("epson/printer/http/" + port + "/modConcluded");
    modConcludedUrl = get_kb_item("epson/printer/http/" + port + "/modConcludedUrl");
    versConcluded = get_kb_item("epson/printer/http/" + port + "/versConcluded");
    versConcludedUrl = get_kb_item("epson/printer/http/" + port + "/versConcludedUrl");
    if ((modConcluded && modConcludedUrl) || (versConcluded && versConcludedUrl)) {
      extra += '  Concluded from version/product identification result and location:\n';
      if (modConcluded)
        extra += '    Model:   ' + modConcluded + ' from URL ' + modConcludedUrl + '\n';

      if (versConcluded)
        extra += '    Version: ' + versConcluded + ' from URL ' + versConcludedUrl + '\n';
    }
  }
}

if (snmp_ports = get_kb_list("epson/printer/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concludedMod = get_kb_item("epson/printer/snmp/" + port + "/concludedMod");
    concludedModOID = get_kb_item("epson/printer/snmp/" + port + "/concludedModOID");
    if (concludedMod && concludedModOID)
      extra += '  Model concluded from "' + concludedMod + '" via OID: ' + concludedModOID + '\n';

    concludedFwOID = get_kb_item("epson/printer/snmp/" + port + "/concludedFwOID");
    if (concludedFwOID)
      extra += '  Version concluded via OID: ' + concludedFwOID + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (pjl_ports = get_kb_list("epson/printer/hp-pjl/port")) {
  foreach port (pjl_ports) {
    extra += 'PJL on port ' + port + '/tcp\n';

    concluded = get_kb_item("epson/printer/hp-pjl/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from PJL banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "hp-pjl");
    register_product(cpe: hw_cpe, location: location, port: port, service: "hp-pjl");
  }
}

if (ftp_ports = get_kb_list("epson/printer/ftp/port")) {
  foreach port (ftp_ports) {
    extra += 'FTP on port ' + port + '/tcp\n';

    concluded  = get_kb_item("epson/printer/ftp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from FTP banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ftp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ftp");
  }
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Epson Printer Detection Consolidation");

report  = build_detection_report(app: os_name, version: detected_fw_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, install: location, cpe: hw_cpe, skip_version: TRUE);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

pref = get_kb_item("global_settings/exclude_printers");
if (pref == "yes") {
  log_message(port: 0, data: 'The remote host is a printer. The scan has been disabled against this host.\n' +
                             'If you want to scan the remote host, uncheck the "Exclude printers from scan" ' +
                             'option and re-scan it.');
  set_kb_item(name:"Host/dead", value:TRUE);
}

exit(0);
