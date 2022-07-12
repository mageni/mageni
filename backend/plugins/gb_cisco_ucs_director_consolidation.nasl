# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144564");
  script_version("2020-09-23T09:17:45+0000");
  script_tag(name:"last_modification", value:"2020-09-23 09:17:45 +0000 (Wed, 23 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-11 07:35:31 +0000 (Fri, 11 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco UCS Director Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ucs_director_ssh_login_detect.nasl", "gb_cisco_ucs_director_http_detect.nasl");
  script_mandatory_keys("cisco/ucs_director/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco UCS Director detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/servers-unified-computing/ucs-director/index.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("cisco/ucs_director/detected"))
  exit(0);

detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("cisco/ucs_director/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("cisco/ucs_director/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "cisco/ucs_director/build", value: detected_build);
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:ucs_director:");
if (!cpe)
  cpe = "cpe:/a:cisco:ucs_director";

register_and_report_os(os: "CentOS", cpe: "cpe:/o:centos:centos",
                       desc: "Cisco UCS Director Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("cisco/ucs_director/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concUrl = get_kb_item("cisco/ucs_director/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (sshlogin_ports = get_kb_list("cisco/ucs_director/ssh-login/port")) {
  foreach port (sshlogin_ports) {
    extra += 'SSH-Login on port ' + port + '/tcp\n';

    concluded = get_kb_item("cisco/ucs_director/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded;

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report = build_detection_report(app: "Cisco UCS Director", version: detected_version, install: location,
                                cpe: cpe, extra: "Build: " + detected_build);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
