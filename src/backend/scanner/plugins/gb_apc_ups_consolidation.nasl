# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151362");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-07 07:22:02 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("APC UPS Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_apc_ups_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_apc_ups_snmp_detect.nasl",
                        "gsf/gb_apc_ups_ftp_detect.nasl");
  script_mandatory_keys("apc/ups/detected");

  script_tag(name:"summary", value:"Consolidation of APC UPS device detections.");

  script_xref(name:"URL", value:"https://www.apc.com/us/en/product-category/88972-uninterruptible-power-supply-ups/");

  exit(0);
}

if (!get_kb_item("apc/ups/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model_type = "unknown";
detected_model = "unknown";
detected_version = "unknown";
location = "/";

# Currently only via snmp extracted
foreach source (make_list("snmp")) {
  model_type_list = get_kb_list("apc/ups/" + source + "/*/model_type");
  foreach model_type (model_type_list) {
    if (model_type != "unknown" && detected_model_type == "unknown") {
      detected_model_type = model_type;
      set_kb_item(name: "apc/upc/model_type", value: detected_model_type);
      break;
    }
  }

  model_list = get_kb_list("apc/ups/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "apc/upc/model", value: detected_model);
      break;
    }
  }

  version_list = get_kb_list("apc/ups/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

if (detected_model != "unknown" || detected_model_type != "unknown") {
  if (detected_model_type != "unknown") {
    os_name = "APC UPS " + detected_model_type + " Firmware";
    cpe_mod_type = str_replace(string: detected_model_type, find: " ", replace: "_");
    os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                       base: "cpe:/o:schneider-electric:ups_" + tolower(cpe_mod_type) + "_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:schneider-electric:ups_" + tolower(cpe_mod_type) + "_firmware";
  } else {
    os_name = "APC UPS " + detected_model + " Firmware";
    os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                       base: "cpe:/o:schneider-electric:ups_" + tolower(detected_model) + "_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:schneider-electric:ups_" + tolower(detected_model) + "_firmware";
  }

  if (detected_model != "unknown") {
    hw_name = "APC UPS " + detected_model;
    hw_cpe = "cpe:/h:schneider-electric:" + tolower(detected_model);
  } else {
    hw_name = "APC UPS " + detected_model_type;
    cpe_mod_type = str_replace(string: detected_model_type, find: " ", replace: "_");
    hw_cpe = "cpe:/h:schneider-electric:" + tolower(cpe_mod_type);
  }
} else {
  os_name = "APC UPS Firmware";
  hw_name = "APC UPS Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:schneider-electric:ups_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:schneider-electric:ups_firmware";

  hw_cpe = "cpe:/h:schneider-electric:ups";
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "APC UPS Detection Consolidation");

if (http_ports = get_kb_list("apc/ups/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port: " + port + '/tcp\n';

    conclUrl = get_kb_item("apc/ups/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("apc/ups/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port: " + port + '/udp\n';

    conclModType = get_kb_item("apc/ups/snmp/" + port + "/concludedModType");
    conclModTypeOID = get_kb_item("apc/ups/snmp/" + port + "/concludedModTypeOID");
    if (conclModType && conclModTypeOID)
      extra += '  Model Type concluded from: "' + conclModType + '" via OID: "' + conclModTypeOID + '"\n';

    conclMod = get_kb_item("apc/ups/snmp/" + port + "/concludedMod");
    conclModOID = get_kb_item("apc/ups/snmp/" + port + "/concludedModOID");
    if (conclMod && conclModOID)
      extra += '  Model concluded from: "' + conclMod + '" via OID: "' + conclModOID + '"\n';

    conclVers = get_kb_item("apc/ups/snmp/" + port + "/concludedVers");
    conclVersOID = get_kb_item("apc/ups/snmp/" + port + "/concludedVersOID");
    if (conclVers && conclVersOID)
      extra += '  Version concluded from: "' + conclVers + '" via OID: "' + conclVersOID + '"\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ftp_ports = get_kb_list("apc/ups/ftp/port")) {
  foreach port (ftp_ports) {
    extra += "FTP on port: " + port + '/tcp\n';

    concluded = get_kb_item("apc/ups/ftp/" + port + "/concluded");
    if (concluded)
      extra += "  FTP Banner: " + concluded + '\n';

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

log_message(port: 0, data: chomp(report));

exit(0);
