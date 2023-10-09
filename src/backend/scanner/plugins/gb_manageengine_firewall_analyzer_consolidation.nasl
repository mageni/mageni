# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150884");
  script_version("2023-08-18T16:09:48+0000");
  script_tag(name:"last_modification", value:"2023-08-18 16:09:48 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-18 03:39:53 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine Firewall Analyzer Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_manageengine_firewall_analyzer_http_detect.nasl",
                      "gb_manageengine_firewall_analyzer_smb_login_detect.nasl");
  script_mandatory_keys("manageengine/firewall_analyzer/detected");

  script_tag(name:"summary", value:"Consolidation of ManageEngine Firewall Analyzer detections.");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/firewall/");

  exit(0);
}

if (!get_kb_item("manageengine/firewall_analyzer/detected"))
  exit(0);

include("host_details.inc");

detected_version = "unknown";
detected_build = "unknown";
location = "/";
cpe = "cpe:/a:zohocorp:manageengine_firewall_analyzer";

foreach source (make_list("smb", "http")) {
  version_list = get_kb_list("manageengine/firewall_analyzer/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("manageengine/firewall_analyzer/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      break;
    }
  }
}

if (detected_version != "unknown") {
  cpe += ":" + detected_version;
  if (detected_build != "unknown")
    cpe += ":b" + build;
}

if (http_ports = get_kb_list("manageengine/firewall_analyzer/http/port")) {
  extra = '\n- Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {
    extra += "    Port:  " + port + '/tcp\n';

    concluded = get_kb_item("manageengine/firewall_analyzer/http/" + port + "/concluded");
    if (concluded)
      extra += "    Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("manageengine/firewall_analyzer/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "    Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (!isnull(concl = get_kb_item("manageengine/firewall_analyzer/smb/0/concluded"))) {
  if (extra)
    extra += '\n';

  extra += '\n- Local Detection over SMB:\n';

  loc = get_kb_item("manageengine/firewall_analyzer/smb/0/location");
  extra += "    Location:      " + loc + '\n';
  extra += '    Concluded from:\n' + concl + '\n';

  register_product(cpe: cpe, location: loc, port: 0, service: "smb-login");
}

report = build_detection_report(app: "ManageEngine Firewall Analyzer", version: detected_version,
                                patch: detected_build, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
