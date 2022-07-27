###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Firepower Management Center Detection Consolidation
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105522");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-04-03T05:47:31+0000");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2016-01-19 18:05:56 +0100 (Tue, 19 Jan 2016)");

  script_name("Cisco Firepower Management Center Detection Consolidation");

  script_tag(name:"summary", value:"Reports the Cisco Firepower Management Center model and version.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firepower_management_center_ssh_detect.nasl", "gb_cisco_firepower_management_center_http_detect.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");

  exit(0);
}

if (!get_kb_item("cisco/firepower_management_center/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  model_list = get_kb_list("cisco/firepower_management_center/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cisco/firepower_management_center/model", value: model);
      break;
    }
  }

  version_list = get_kb_list("cisco/firepower_management_center/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("cisco/firepower_management_center/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "cisco/firepower_management_center/build", value: build);
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:firepower_management_center:");
if (!cpe)
  cpe = "cpe:/a:cisco:firepower_management_center";

if (http_ports = get_kb_list("cisco/firepower_management_center/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (ssh_login_ports = get_kb_list("cisco/firepower_management_center/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += 'SSH-Login on port ' + port + '/tcp\n';

    concluded = get_kb_item("cisco/firepower_management_center/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report  = build_detection_report(app: "Cisco Firepower Management Center", version: detected_version,
                                 install: location, cpe: cpe,
                                 extra: 'Build: ' + detected_build + '\nModel: ' + detected_model);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
