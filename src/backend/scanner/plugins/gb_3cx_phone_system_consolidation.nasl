# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102062");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-05 09:56:00 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("3CX Phone System Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of 3CX Phone System detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_3cx_phone_system_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_3cx_phone_system_sip_detect.nasl");
  script_mandatory_keys("3cx/phone_system/detected");

  script_xref(name:"URL", value:"https://www.3cx.com/");

  exit(0);
}

if (!get_kb_item("3cx/phone_system/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source (make_list("http", "sip")) {
  version_list = get_kb_list("3cx/phone_system/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", base: "cpe:/a:3cx:3cx:");
if (!cpe)
  cpe = "cpe:/a:3cx:3cx";

if (http_ports = get_kb_list("3cx/phone_system/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("3cx/phone_system/http/" + port + "/concluded");
    concUrl = get_kb_item("3cx/phone_system/http/" + port + "/concludedUrl");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    if (concUrl)
      extra += "  Concluded from version/product identification location: " + concUrl + '\n';

    register_product(cpe: cpe, location: port + "/tcp", port: port, service: "www");
  }
}

if (sip_ports = get_kb_list("3cx/phone_system/sip/port")) {
  foreach port (sip_ports) {
    proto = get_kb_item("3cx/phone_system/sip/" + port + "/proto");
    extra += "SIP on port " + port + "/" + proto + '\n';
    concluded = get_kb_item("3cx/phone_system/sip/" + port + "/concluded");
    if (concluded)
      extra += "  SIP Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: port + "/" + proto, port: port, service: "sip", proto: proto);
  }
}

report = build_detection_report(app: "3CX Phone System", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
