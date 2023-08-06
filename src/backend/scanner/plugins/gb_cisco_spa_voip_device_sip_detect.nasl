# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106216");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-01 10:53:52 +0700 (Thu, 01 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Small Business SPA Series VoIP Device Detection (SIP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"SIP based detection of Cisco Small Business SPA Series VoIP
  devices.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/collaboration-endpoints/ip-phones/index.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("sip.inc");

infos = sip_get_port_proto(default_port: "5060", default_proto: "udp");
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner(port: port, proto: proto);

# Server: Cisco/SPA303-7.4.8a
# Server: Cisco/SPA122-1.4.1(SR5)
# Server: Cisco/SPA504G-7.6.2c
if (banner && "Cisco/SPA" >< banner) {
  version = "unknown";
  model = "unknown";
  location = "/";
  concluded = banner;

  set_kb_item(name: "cisco/spa_voip/detected", value: TRUE);
  set_kb_item(name: "cisco/spa_voip/sip/detected", value: TRUE);

  mo = eregmatch(pattern: "Cisco\/(SPA[0-9A-Z]+)", string: banner);
  if (!isnull(mo[1]))
    model = mo[1];

  vers = eregmatch(pattern: "/SPA[0-9A-Z]+-([0-9A-Za-z_.]+)", string: banner);
  if (!isnull(vers[1]))
    version = ereg_replace(string: vers[1], pattern: "\(([0-9A-Za-z_]+)\)", replace: ".\1");

  if (model != "unknown") {
    os_name = "Cisco " + model + " Firmware";
    hw_name = "Cisco " + model;

    os_cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z_.]+)",
                       base: "cpe:/o:cisco:" + tolower(model) + "_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:cisco:" + tolower(model) + "_firmware";

    hw_cpe = "cpe:/h:cisco:" + tolower(model);
  } else {
    os_name = "Cisco SPA Firmware";
    hw_name = "Cisco SPA Unknown Model";

    os_cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z_.]+)", base: "cpe:/o:cisco:spa_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:cisco:spa_firmware";

    hw_cpe = "cpe:/h:cisco:spa";
  }

  os_register_and_report(os: os_name, cpe: os_cpe, banner_type: "SIP server banner", port: port,
                         proto: proto, banner: chomp(banner),
                         desc: "Cisco Small Business SPA Series VoIP Device Detection (SIP)", runs_key: "unixoide");

  register_product(cpe: os_cpe, port: port, location: location, service: "sip", proto: proto);
  register_product(cpe: hw_cpe, port: port, location: location, service: "sip", proto: proto);

  report  = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe,
                                   concluded: chomp(banner));
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: "/", cpe: hw_cpe);

  log_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(0);
