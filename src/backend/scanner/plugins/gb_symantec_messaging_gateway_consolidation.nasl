# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103612");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-05-17 13:22:07 +0200 (Tue, 17 May 2016)");

  script_name("Symantec Messaging Gateway Detection Consolidation");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_symantec_messaging_gateway_http_detect.nasl",
                      "gb_symantec_messaging_gateway_ssh_detect.nasl",
                      "gb_symantec_messaging_gateway_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_symantec_messaging_gateway_smtp_detect.nasl");
  script_mandatory_keys("symantec/smg/detected");

  script_tag(name:"summary", value:"Consolidation of Symantec Messaging Gateway detections.");

  script_xref(name:"URL", value:"https://www.broadcom.com/products/cybersecurity/email/gateway");

  exit(0);
}

if (!get_kb_item("symantec/smg/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_patch = "unknown";
location = "/";

# nb: No version extraction via SMTP
foreach source (make_list("ssh-login", "snmp", "http")) {
  version_list = get_kb_list("symantec/smg/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  patch_list = get_kb_list("symantec/smg/" + source + "/*/patch");
  foreach patch (patch_list) {
    if (patch != "unknown" && detected_patch == "unknown") {
      detected_patch = patch;
      set_kb_item(name: "symantec/smg/patch", value: detected_patch);
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:symantec:messaging_gateway:");
if (!cpe)
  cpe = "cpe:/a:symantec:messaging_gateway";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "Symantec Messaging Gateway Detection Consolidation");

if (http_ports = get_kb_list("symantec/smg/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP on port " + port + '/tcp\n';

    concluded = get_kb_item("symantec/smg/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("symantec/smg/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: cpe, location: port + '/', port: port, service: "www");
  }
}


if (ssh_ports = get_kb_list("symantec/smg/ssh-login/port")) {
  foreach port (ssh_ports) {
    extra += "SSH login via port " + port + '/tcp\n';

    concluded = get_kb_item("symantec/smg/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}


if (snmp_ports = get_kb_list("symantec/smg/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    register_product(cpe: cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (smtp_ports = get_kb_list("symantec/smg/smtp/port")) {
  foreach port (smtp_ports) {
    extra += "SMTP on port " + port + '/tcp\n';

    concluded = get_kb_item("symantec/smg/smtp/" + port + "/concluded");
    if (concluded)
      extra += "  SMTP banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "smtp");
  }
}

report = build_detection_report(app: "Symantec Messaging Gateway", version: detected_version,
                                install: location, cpe: cpe, patch: detected_patch);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
