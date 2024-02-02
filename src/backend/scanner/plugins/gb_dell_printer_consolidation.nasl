# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151376");
  script_version("2023-12-21T05:06:40+0000");
  script_tag(name:"last_modification", value:"2023-12-21 05:06:40 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-12 04:26:53 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell Printer Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_dell_printer_snmp_detect.nasl",
                      "gb_dell_printer_pjl_detect.nasl",
                      "gb_dell_printer_ftp_detect.nasl",
                      "gb_dell_printer_http_detect.nasl",
                      "global_settings.nasl");
  script_mandatory_keys("dell/printer/detected");

  script_tag(name:"summary", value:"Consolidation of Dell Printer device detections.");

  script_xref(name:"URL", value:"https://www.dell.com");

  exit(0);
}

if (!get_kb_item("dell/printer/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("http", "snmp", "hp-pjl", "ftp")) {
  model_list = get_kb_list("dell/printer/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "dell/printer/model", value: model);
      break;
    }
  }

  version_list = get_kb_list("dell/printer/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_name = "Dell Printer ";
hw_name = os_name;

if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;

  cpe_model = str_replace(string: tolower(detected_model), find: " ", replace: "_");

  os_cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9a-z_.-]+)",
                     base: "cpe:/o:dell:" + cpe_model + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:dell:" + cpe_model + "_firmware";

  hw_cpe = "cpe:/h:dell:" + cpe_model;
} else {
  os_name += " Unknown Model Firmware";
  hw_name += " Unknown Model";

  os_cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9a-z_.-]+)",
                     base : "cpe:/o:dell:printer_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:dell:printer_firmware";

  hw_cpe = "cpe:/h:dell:printer";
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Dell Printer Detection Consolidation");

if (http_ports = get_kb_list("dell/printer/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("dell/printer/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    conclUrl = get_kb_item("dell/printer/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("dell/printer/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    banner = get_kb_item("dell/printer/snmp/" + port + "/banner");
    if (banner)
      extra += "  SNMP Banner: " + banner + '\n';

    concludedMod = get_kb_item("dell/printer/snmp/" + port + "/concludedMod");
    concludedModOID = get_kb_item("dell/printer/snmp/" + port + "/concludedModOID");
    if (concludedMod && concludedModOID)
      extra += '  Model concluded from "' + concludedMod + '" via OID: ' + concludedModOID + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (pjl_ports = get_kb_list("dell/printer/hp-pjl/port")) {
  foreach port (pjl_ports) {
    extra += "PJL on port " + port + '/tcp\n';

    concluded = get_kb_item("dell/printer/hp-pjl/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from PJL banner: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "hp-pjl");
    register_product(cpe: hw_cpe, location: location, port: port, service: "hp-pjl");
  }
}

if (ftp_ports = get_kb_list("dell/printer/ftp/port")) {
  foreach port (ftp_ports) {
    extra += "FTP on port " + port + '/tcp\n';

    concluded = get_kb_item("dell/printer/ftp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from FTP banner: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ftp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ftp");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
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
