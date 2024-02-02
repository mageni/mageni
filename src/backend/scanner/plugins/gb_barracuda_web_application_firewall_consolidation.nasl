# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151621");
  script_version("2024-01-30T14:37:03+0000");
  script_tag(name:"last_modification", value:"2024-01-30 14:37:03 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-29 07:39:48 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Barracuda Web Application Firewall Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_barracuda_web_application_firewall_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_barracuda_web_application_firewall_snmp_detect.nasl");
  script_mandatory_keys("barracuda/web_application_firewall/detected");

  script_tag(name:"summary", value:"Consolidation of Barracuda Web Application Firewall detections.");

  script_xref(name:"URL", value:"https://www.barracuda.com/products/application-protection/web-application-firewall");

  exit(0);
}

if (!get_kb_item("barracuda/web_application_firewall/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("snmp", "http")) {
  version_list = get_kb_list("barracuda/web_application_firewall/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:barracuda:web_application_firewall:");
if (!cpe)
  cpe = "cpe:/a:barracuda:web_application_firewall";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "Barracuda Web Application Firewall Detection Consolidation");

if (http_ports = get_kb_list("barracuda/web_application_firewall/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '\n';

    concluded = get_kb_item("barracuda/web_application_firewall/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    concludedUrl = get_kb_item("barracuda/web_application_firewall/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += "  Concluded from version/product identification location: " + concludedUrl + '\n';

    http_extra = get_kb_item("barracuda/web_application_firewall/http/" + port + "/extra");
    if (http_extra)
      extra = chomp(extra) + http_extra;

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("barracuda/web_application_firewall/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '\n';

    concluded = get_kb_item("barracuda/web_application_firewall/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from SNMP OID(s):" + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report = build_detection_report(app: "Barracuda Web Application Firewall", version: detected_version,
                                install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
