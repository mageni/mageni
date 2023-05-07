# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149596");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-28 05:40:32 +0000 (Fri, 28 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MailEnable Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_mailenable_http_detect.nasl",
                      "gb_mailenable_smtp_detect.nasl",
                      "gb_mailenable_pop3_detect.nasl",
                      "gb_mailenable_imap_detect.nasl");
  script_mandatory_keys("mailenable/detected");

  script_tag(name:"summary", value:"Consolidation of MailEnable detections.");

  script_xref(name:"URL", value:"https://www.mailenable.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("mailenable/detected"))
  exit(0);

detected_version = "unknown";
location = "/";

# nb: Only HTTP and SMTP (currently) offers a banner including the version
foreach source (make_list("http", "smtp")) {
  version_list = get_kb_list("mailenable/" + source + "/*/version");
  foreach version (version_list) {
    detected_version = version;
    break;
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:mailenable:mailenable:");
if (!cpe)
  cpe = "cpe:/a:mailenable:mailenable";

os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", runs_key: "windows",
                       desc: "MailEnable Detection Consolidation");

if (http_ports = get_kb_list("mailenable/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("mailenable/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    concUrl = get_kb_item("mailenable/http/" + port + "/concludedUrl");
      extra += "  Concluded from version/product identification location: " + concUrl + '\n';

    loc = get_kb_item("mailenable/http/" + port + "/location");
    if (loc)
      register_product(cpe: cpe, location: loc, port: port, service: "www");
    else
      register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (smtp_ports = get_kb_list("mailenable/smtp/port")) {
  foreach port (smtp_ports) {
    extra += "SMTP on port " + port + '/tcp\n';

    concluded = get_kb_item("mailenable/smtp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "smtp");
  }
}

if (pop3_ports = get_kb_list("mailenable/pop3/port")) {
  foreach port (pop3_ports) {
    extra += "POP3 on port " + port + '/tcp\n';

    concluded = get_kb_item("mailenable/pop3/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "pop3");
  }
}

if (imap_ports = get_kb_list("mailenable/imap/port")) {
  foreach port (imap_ports) {
    extra += "IMAP on port " + port + '/tcp\n';

    concluded = get_kb_item("mailenable/imap/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "imap");
  }
}

report = build_detection_report(app: "MailEnable", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n\n';
  report += chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
