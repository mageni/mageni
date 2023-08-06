# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105271");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-11 16:54:59 +0200 (Mon, 11 May 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix NetScaler Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_citrix_netscaler_ssh_login_detect.nasl",
                      "gb_citrix_netscaler_snmp_detect.nasl",
                      "citrix_netscaler_http_detect.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"summary", value:"Consolidation of Citrix Netscaler detections.");

  script_xref(name:"URL", value:"https://www.citrix.com/products/netscaler-adc/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("citrix/netscaler/detected"))
  exit(0);

detected_version = "unknown";

foreach source (make_list("ssh", "snmp", "http")) {
  if (detected_version != "unknown")
    break;

  version_list = get_kb_list("citrix/netscaler/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      set_kb_item(name: "citrix/netscaler/version", value: version);
      break;
    }
  }
}

if (detected_version != "unknown") {
  cpe    = "cpe:/a:citrix:netscaler:" + detected_version;
  os_cpe = "cpe:/o:citrix:netscaler:" + detected_version;
} else {
  cpe    = "cpe:/a:citrix:netscaler";
  os_cpe = "cpe:/o:citrix:netscaler";
}

if (ssh_ports = get_kb_list("citrix/netscaler/ssh/port")) {
  foreach port (ssh_ports) {
    extra += "SSH on port " + port + '/tcp\n';

    concluded = get_kb_item("citrix/netscaler/ssh/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from: " + concluded + '\n';

    register_product(cpe: cpe, location: port + "/tcp", port: port, service: "ssh");
    register_product(cpe: os_cpe, location: port + "/tcp", port: port, service: "ssh");
  }
}

if (snmp_ports = get_kb_list("citrix/netscaler/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("citrix/netscaler/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from SNMP sysDescr OID: " + concluded + '\n';

    register_product(cpe: cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
  }
}

if (http_ports = get_kb_list("citrix/netscaler/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(S) on port " + port + '/tcp\n';

    concluded = get_kb_item("citrix/netscaler/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from: " + concluded + '\n';
    concUrl = get_kb_item("citrix/netscaler/http/" + port + "/concUrl");
    if (concUrl)
      extra += "  Concluded from version identification location: " + concUrl + '\n';
    detectUrl = get_kb_item("citrix/netscaler/http/" + port + "/detectUrl");
      extra += "  Detected URL: " + detectUrl + '\n';

    register_product(cpe: cpe, location: port + "/tcp", port: port, service: "www");
    register_product(cpe: os_cpe, location: port + "/tcp", port: port, service: "www");
  }
}

os_register_and_report(os: "Citrix NetScaler OS", cpe: os_cpe, runs_key: "unixoide",
                       desc: "Citrix NetScaler Detection Consolidation");

enh_build = get_kb_item("citrix/netscaler/enhanced_build");
if (enh_build)
  enhanced = 'Enhanced Build\n';

report = build_detection_report(app: "Citrix NetScaler", version: version, install: "/", cpe: cpe,
                                extra: enhanced);
if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
