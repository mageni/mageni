# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170523");
  script_version("2023-08-08T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-08-08 05:06:11 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-28 11:23:26 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Fuji Xerox / Fujifilm Printer Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Fuji Xerox / Fujifilm printer detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_fujifilm_printer_http_detect.nasl", "gb_fujifilm_printer_snmp_detect.nasl",
                      "gb_fujifilm_printer_pjl_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("fujifilm/printer/detected");

  script_xref(name:"URL", value:"https://www.fujifilm.com/fbau/en/products/au-printers");
  script_xref(name:"URL", value:"https://www.fujifilm.com/fbau/en/products/au-multifunction-printers");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("fujifilm_printers.inc");

if(!get_kb_item("fujifilm/printer/detected"))
  exit(0);

detected_model = "unknown";
detected_fw_version = "unknown";

foreach source (make_list("snmp", "http", "hp-pjl")) {
  fw_version_list = get_kb_list("fujifilm/printer/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if(fw_version && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      set_kb_item(name: "fujifilm/printer/fw_version", value: fw_version);
      break;
    }
  }

  model_list = get_kb_list("fujifilm/printer/" + source + "/*/model");
  foreach model (model_list) {
    if(model && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "fujifilm/printer/model", value: model);
      break;
    }
  }
}

extra_cpes = FALSE;

os_name = "Fuji Xerox / Fujifilm Printer ";
if(detected_model != "unknown") {
  # nb: Sometimes the model includes a trailing space from the SNMP detection, just get rid of this here
  detected_model = chomp(detected_model);
  if(detected_model !~ "^Apeos ")
    extra_cpes = TRUE;
  os_name += detected_model + " Firmware";
  hw_name += detected_model;

  cpe_model = detected_model;
  cpe_model = tolower(cpe_model);
  if("/" >< cpe_model)
    cpe_model = str_replace(string: cpe_model, find: "/", replace: "%2f");
  cpe_model = str_replace(string: cpe_model, find: " ", replace: "_");
  hw_cpe = "cpe:/h:fujifilm:" + cpe_model;
  os_cpe = str_replace(string: hw_cpe, find: "cpe:/h", replace: "cpe:/o");
  os_cpe += "_firmware";
  if (extra_cpes) {
    extra_hw_cpe = "cpe:/h:fujixerox:" + cpe_model;
    extra_os_cpe = "cpe:/o:fujixerox:" + cpe_model + "_firmware";
  }
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";
  hw_cpe = "cpe:/h:fujifilm:printer";
  os_cpe = "cpe:/o:fujifilm:printer_firmware";
}

if(detected_fw_version != "unknown") {
  os_cpe += ':' + detected_fw_version;
  if(extra_os_cpe)
    extra_os_cpe += ':' + detected_fw_version;
}

location = "/";

if(http_ports = get_kb_list("fujifilm/printer/http/port")) {
  foreach port (http_ports) {
    concluded = get_kb_item("fujifilm/printer/http/" + port + "/concluded");
    concUrl = get_kb_item("fujifilm/printer/http/" + port + "/concludedUrl");

    extra += "HTTP(s) on port " + port + '/tcp\n';
    if(concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';
    if(concUrl)
      extra += '  Concluded from version/product identification location:\n' + concUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
    if(extra_hw_cpe)
      register_product(cpe: extra_hw_cpe, location: location, port: port, service: "www");
    if(extra_os_cpe)
      register_product(cpe: extra_os_cpe, location: location, port: port, service: "www");
  }
}

if(snmp_ports = get_kb_list("fujifilm/printer/snmp/port")) {
  foreach port(snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("fujifilm/printer/snmp/" + port + "/concluded");
    if(concluded)
      extra += "  Concluded from SNMP sysDescr OID: " + concluded + '\n';

    concludedFwOID = get_kb_item("fujifilm/printer/snmp/" + port + "/concludedFwOID");
    if(concludedFwOID)
      extra += "  Version concluded via OID: " + concludedFwOID + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
    if(extra_hw_cpe)
      register_product(cpe: extra_hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
    if(extra_os_cpe)
      register_product(cpe: extra_os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if(pjl_ports = get_kb_list("fujifilm/printer/hp-pjl/port")) {
  foreach port(pjl_ports) {
    extra += "PJL on port " + port + '/tcp\n';

    concluded = get_kb_item("fujifilm/printer/hp-pjl/" + port + "/concluded");
    if(concluded)
      extra += "  Concluded from PJL banner: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "hp-pjl");
    register_product(cpe: hw_cpe, location: location, port: port, service: "hp-pjl");
    if(extra_hw_cpe)
      register_product(cpe: extra_hw_cpe, location: location, port: port, service: "hp-pjl");
    if(extra_os_cpe)
      register_product(cpe: extra_os_cpe, location: location, port: port, service: "hp-pjl");
  }
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Fuji Xerox / Fujifilm Printer Detection Consolidation", runs_key: "unixoide");

report += build_detection_report(app: os_name, version: detected_fw_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

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
