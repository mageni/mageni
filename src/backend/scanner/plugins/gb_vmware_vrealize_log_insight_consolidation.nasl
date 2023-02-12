# Copyright (C) 2023 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149235");
  script_version("2023-02-09T10:17:23+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-03 04:49:44 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VMware vRealize Log Insight Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_vmware_vrealize_log_insight_http_detect.nasl",
                      "gb_vmware_vrealize_log_insight_ssh_login_detect.nasl");
  script_mandatory_keys("vmware/vrealize_log_insight/detected");

  script_tag(name:"summary", value:"Consolidation of VMware vRealize Log Insight detections.");

  script_xref(name:"URL", value:"https://www.vmware.com/products/aria-operations-for-logs.html");

  exit(0);
}

if (!get_kb_item("vmware/vrealize_log_insight/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("vmware/vrealize_log_insight/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("vmware/vrealize_log_insight/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "vmware/vrealize_log_insight/build", value: detected_build);
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:vmware:vrealize_log_insight:");
if (!cpe)
  cpe = "cpe:/a:vmware:vrealize_log_insight";

os_register_and_report(os: "VMware Photon OS", cpe: "cpe:/o:vmware:photonos", runs_key: "unixoide",
                       desc: "VMware vRealize Log Insight Detection Consolidation");

if (http_ports = get_kb_list("vmware/vrealize_log_insight/http/port")) {
  extra += 'Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {
    extra += "  Port: " + port + '/tcp\n';

    concluded = get_kb_item("vmware/vrealize_log_insight/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    concUrl = get_kb_item("vmware/vrealize_log_insight/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location:\n' + concUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (ssh_login_ports = get_kb_list("vmware/vrealize_log_insight/ssh-login/port")) {
  if (extra)
    extra += '\n';

  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    extra += "  Port: " + port + '/tcp\n';
    concluded = get_kb_item("vmware/vrealize_log_insight/ssh-login/" + port + "/concluded");
    if (concluded) {
      if (!cmd = get_kb_item("vmware/vrealize_log_insight/ssh-login/" + port + "/concluded_cmd"))
        cmd = "unknown";
      extra += "  Concluded from '" + cmd + "'" + ' command:\n' + concluded + '\n';
    }

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report = build_detection_report(app: "VMware vRealize Log Insight", version: detected_version,
                                build: detected_build, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: chomp(report));

exit(0);
