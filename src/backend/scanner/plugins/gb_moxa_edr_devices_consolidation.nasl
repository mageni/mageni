# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151042");
  script_version("2023-09-26T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-09-26 05:05:30 +0000 (Tue, 26 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-25 07:26:43 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa EDR Router Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_moxa_edr_devices_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_moxa_edr_devices_snmp_detect.nasl");
  script_mandatory_keys("moxa/edr/detected");

  script_tag(name:"summary", value:"Consolidation of Moxa EDR Router device detections.");

  script_xref(name:"URL", value:"https://www.moxa.com/en/products/industrial-network-infrastructure/secure-routers/secure-routers");

  exit(0);
}

if (!get_kb_item("moxa/edr/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("snmp", "http")) {
  model_list = get_kb_list("moxa/edr/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "moxa/edr/model", value: model);
      break;
    }
  }

  version_list = get_kb_list("moxa/edr/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = "Moxa " + detected_model + " Firmware";
  hw_name = "Moxa " + detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:moxa:" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:moxa:" + tolower(detected_model);
} else {
  os_name = "Moxa EDR Firmware";
  hw_name = "Moxa EDR Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:moxa:edr_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:edr_firmware";

  hw_cpe = "cpe:/h:moxa:edr_router";
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Moxa EDR Router Detection Consolidation");

if (http_ports = get_kb_list("moxa/edr/http/port")) {
  foreach port (http_ports) {
    extra = "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("moxa/edr/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("moxa/edr/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("moxa/edr/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    conclMod = get_kb_item("moxa/edr/snmp/" + port + "/concludedMod");
    conclModOID = get_kb_item("moxa/edr/snmp/" + port + "/concludedModOID");
    if (conclMod && conclModOID)
      extra += '  Model concluded from "' + conclMod + '" via OID: ' + conclModOID + '\n';

    conclVers = get_kb_item("moxa/edr/snmp/" + port + "/concludedVers");
    conclVersOID = get_kb_item("moxa/edr/snmp/" + port + "/concludedVersOID");
    if (conclVers && conclVersOID)
      extra += '  Version concluded from "' + conclMod + '" via OID: ' + conclModOID + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
