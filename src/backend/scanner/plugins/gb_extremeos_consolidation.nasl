# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151229");
  script_version("2023-10-24T14:40:27+0000");
  script_tag(name:"last_modification", value:"2023-10-24 14:40:27 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-18 07:59:16 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Extreme ExtremeXOS (EXOS) Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_extremeos_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_extremeos_http_detect.nasl",
                        "gsf/gb_extremeos_telnet_detect.nasl");
  script_mandatory_keys("extreme/exos/detected");

  script_tag(name:"summary", value:"Consolidation of Extreme ExtremeXOS (EXOS) detections.");

  script_xref(name:"URL", value:"https://www.extremenetworks.com/");

  exit(0);
}

if (!get_kb_item("extreme/exos/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_patch = "none / unknown";
location = "/";

# nb: Currently only via SNMP extracted
foreach source (make_list("snmp")) {
  model_list = get_kb_list("extreme/exos/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "extreme/exos/model", value: detected_model);
      break;
    }
  }

  version_list = get_kb_list("extreme/exos/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  patch_list = get_kb_list("extreme/exos/" + source + "/*/patch");
  foreach patch (patch_list) {
    if (patch != "None" && detected_patch == "none / unknown") {
      detected_patch = patch;
      set_kb_item(name: "extreme/exos/patch", value: detected_patch);
      break;
    }
  }
}

os_name = "Extreme ExtremeXOS (EXOS)";
os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:extremenetworks:exos:");
if (!os_cpe)
  os_cpe = "cpe:/o:extremenetworks:exos";

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Extreme ExtremeXOS (EXOS) Detection Consolidation");

if (detected_model != "unknown") {
  hw_name = "Extreme Networks " + detected_model;
  hw_cpe = "cpe:/h:extremenetworks:" + tolower(detected_model);
} else {
  hw_name = "Extreme Networks Unknown Model";
  hw_cpe = "cpe:/h:extremenetworks:switch";
}

if (http_ports = get_kb_list("extreme/exos/http/port")) {
  foreach port (http_ports) {
    extra = "HTTP(s) on port " + port + '/tcp\n';

    conclUrl = get_kb_item("extreme/exos/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("extreme/exos/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("extreme/exos/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  SNMP banner: " + concluded + '\n';

    conclMod = get_kb_item("extreme/exos/snmp/" + port + "/concludedMod");
    conclModOID = get_kb_item("extreme/exos/snmp/" + port + "/concludedModOID");
    if (conclMod && conclModOID)
      extra += '  Model concluded from "' + conclMod + '" via OID: ' + conclModOID + '\n';

    conclVers = get_kb_item("extreme/exos/snmp/" + port + "/concludedVers");
    conclVersOID = get_kb_item("extreme/exos/snmp/" + port + "/concludedVersOID");
    if (conclVers && conclVersOID)
      extra += '  Model concluded from "' + conclMod + '" via OID: ' + conclVersOID + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (telnet_ports = get_kb_list("extreme/exos/telnet/port")) {
  foreach port (telnet_ports) {
    extra += "Telnet on port " + port + '/tcp\n';

    concluded = get_kb_item("extreme/exos/telnet/" + port + "/concluded");
    if (concluded)
      extra += '\n  Telnet Banner: ' + chomp(concluded) + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, patch: detected_patch,
                                 install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
