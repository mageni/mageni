# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151406");
  script_version("2023-12-15T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-15 05:22:04 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MLDonkey Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("mldonkey_http_detect.nasl",
                      "mldonkey_telnet_detect.nasl");
  script_mandatory_keys("mldonkey/detected");

  script_tag(name:"summary", value:"Consolidation of MLDonkey detections.");

  script_xref(name:"URL", value:"https://sourceforge.net/projects/mldonkey/");

  exit(0);
}

if (!get_kb_item("mldonkey/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("http", "telnet")) {
  version_list = get_kb_list("mldonkey/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:mldonkey:mldonkey:");
if (!cpe)
  cpe = "cpe:/a:mldonkey:mldonkey";

if (http_ports = get_kb_list("mldonkey/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("mldonkey/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("mldonkey/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (telnet_ports = get_kb_list("mldonkey/telnet/port")) {
  foreach port (telnet_ports) {
    extra += "Telnet on port: " + port + '/tcp\n';

    concluded = get_kb_item("mldonkey/telnet/" + port + "/concluded");
    if (concluded)
      extra += " Concluded from: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "telnet");
  }
}

report  = build_detection_report(app: "MLDonkey", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
