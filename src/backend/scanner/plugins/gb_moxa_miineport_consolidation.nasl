# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149646");
  script_version("2023-05-12T16:07:31+0000");
  script_tag(name:"last_modification", value:"2023-05-12 16:07:31 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-05 05:11:06 +0000 (Fri, 05 May 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa MiiNePort Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_moxa_miineport_telnet_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_moxa_miineport_http_detect.nasl",
                        "gsf/gb_moxa_miineport_snmp_detect.nasl");
  script_mandatory_keys("moxa/miineport/detected");

  script_tag(name:"summary", value:"Consolidation of Moxa MiiNePort device detections.");

  script_xref(name:"URL", value:"https://www.moxa.com");

  exit(0);
}

if (!get_kb_item("moxa/miineport/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
location = "/";

# nb:
# - HTTP only provides the model, build and version if "unprotected"
# - SNMP currently only provides the model
foreach source (make_list("telnet", "snmp", "http")) {
  model_list = get_kb_list("moxa/miineport/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  version_list = get_kb_list("moxa/miineport/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("moxa/miineport/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "moxa/miineport/build", value: detected_build);
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = "Moxa MiiNePort " + detected_model + " Firmware";
  hw_name = "Moxa MiiNePort " + detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:moxa:miineport_" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:miineport_" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:moxa:miineport_" + tolower(detected_model);
} else {
  os_name = "Moxa MiiNePort Firmware";
  hw_name = "Moxa MiiNePort Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:moxa:miineport_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:miineport_firmware";

  hw_cpe = "cpe:/h:moxa:miineport";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Moxa MiiNePort Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("moxa/miineport/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("moxa/miineport/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    conclUrl = get_kb_item("moxa/miineport/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("moxa/miineport/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("moxa/miineport/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from SNMP sysDescr OID: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (telnet_ports = get_kb_list("moxa/miineport/telnet/port")) {
  foreach port (telnet_ports) {
    extra += "Telnet on port " + port + '/tcp\n';

    concluded = get_kb_item("moxa/miineport/telnet/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from banner:\n' + concluded;

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe,
                                 extra: "Build: " + detected_build);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
