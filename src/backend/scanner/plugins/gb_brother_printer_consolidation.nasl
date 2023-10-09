# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170550");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-22 14:43:18 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Brother Printer Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Brother Printer device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_brother_printer_http_detect.nasl", "gb_brother_printer_snmp_detect.nasl",
                      "gb_brother_printer_pjl_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("brother/printer/detected");

  script_xref(name:"URL", value:"https://www.brother-usa.com/home/printers-fax");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("brother/printer/detected"))
  exit(0);

detected_model = "unknown";
detected_fw_version = "unknown";
location = "/";

foreach source (make_list("http", "snmp", "hp-pjl")) {
  model_list = get_kb_list("brother/printer/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "brother/printer/model", value: model);
      break;
    }
  }

  fw_version_list = get_kb_list("brother/printer/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version != "unknown" && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      break;
    }
  }
}

os_name = "Brother Printer ";
hw_name = os_name;

if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;
  cpe_model = str_replace(string: tolower(detected_model), find: " ", replace: "_");

  if (detected_fw_version != "unknown")
    os_cpe = build_cpe(value: tolower(detected_fw_version), exp: "^([0-9a-z.]+)",
                       base: "cpe:/o:brother:" + cpe_model + "_firmware:");
  else
    os_cpe = "cpe:/o:brother:" + cpe_model + "_firmware";

  hw_cpe = "cpe:/h:brother:" + cpe_model;
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";

  if (detected_fw_version != "unknown")
    os_cpe = build_cpe(value: tolower(detected_fw_version), exp: "^([0-9a-z.]+)",
                       base: "cpe:/o:brother:printer_firmware:");
  else
    os_cpe = "cpe:/o:brother:printer_firmware";

  hw_cpe = "cpe:/h:brother:printer";
}

if (http_ports = get_kb_list("brother/printer/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    modConcluded = get_kb_item("brother/printer/http/" + port + "/modConcluded");
    modConcludedUrl = get_kb_item("brother/printer/http/" + port + "/modConcludedUrl");
    versConcluded = get_kb_item("brother/printer/http/" + port + "/versConcluded");
    versConcludedUrl = get_kb_item("brother/printer/http/" + port + "/versConcludedUrl");
    if ((modConcluded && modConcludedUrl) || (versConcluded && versConcludedUrl)) {
      extra += '  Concluded from version/product identification result and location:\n';
      if (modConcluded)
        extra += '    Model:   ' + modConcluded + ' from URL ' + modConcludedUrl + '\n';

      if (versConcluded)
        extra += '    Version: ' + versConcluded + ' from URL ' + versConcludedUrl + '\n';
    }

    generalConcluded = get_kb_item("brother/printer/http/" + port + "/generalConcluded");
    if (generalConcluded) {
      extra += '  Concluded from product identification result:\n';
      extra += '    HTTP banner: ' + generalConcluded + '\n';
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("brother/printer/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concludedMod = get_kb_item("brother/printer/snmp/" + port + "/concludedMod");
    concludedModOID = get_kb_item("brother/printer/snmp/" + port + "/concludedModOID");
    if (concludedMod && concludedModOID)
      extra += '  Model concluded from "' + concludedMod + '" via OID: ' + concludedModOID + '\n';

    concludedFwOID = get_kb_item("brother/printer/snmp/" + port + "/concludedFwOID");
    if (concludedFwOID)
      extra += '  Version concluded via OID: ' + concludedFwOID + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (pjl_ports = get_kb_list("brother/printer/hp-pjl/port")) {
  foreach port (pjl_ports) {
    extra += 'PJL on port ' + port + '/tcp\n';

    concluded = get_kb_item("brother/printer/hp-pjl/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from PJL banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "hp-pjl");
    register_product(cpe: hw_cpe, location: location, port: port, service: "hp-pjl");
  }
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Brother Printer Detection Consolidation");

report  = build_detection_report(app: os_name, version: detected_fw_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, install: location, cpe: hw_cpe, skip_version: TRUE);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

pref = get_kb_item("global_settings/exclude_printers");
if (pref == "yes") {
  log_message(port: 0, data: 'The remote host is a printer. The scan has been disabled against this host.\n' +
                             'If you want to scan the remote host, uncheck the "Exclude printers from scan" ' +
                             'option and re-scan it.');
  set_kb_item(name: "Host/dead", value: TRUE);
}

exit(0);