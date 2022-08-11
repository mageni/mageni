# Copyright (C) 2022 Greenbone Networks GmbH
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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147697");
  script_version("2022-02-24T09:13:28+0000");
  script_tag(name:"last_modification", value:"2022-02-24 09:13:28 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-24 06:30:09 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VMware NSX Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of VMware NSX detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_vmware_nsx_ssh_login_detect.nasl",
                      "gb_vmware_nsx_http_detect.nasl",
                      "gb_vmware_nsx_http_api_detect.nasl");
  script_mandatory_keys("vmware/nsx/detected");

  script_xref(name:"URL", value:"https://www.vmware.com/products/nsx.html");

  exit(0);
}

if (!get_kb_item("vmware/nsx/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http-api", "http")) {
  version_list = get_kb_list("vmware/nsx/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("vmware/nsx/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "vmware/nsx/build", value: detected_build);
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:vmware:nsx:");
if (!cpe)
  cpe = "cpe:/a:vmware:nsx";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "VMware NSX Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("vmware/nsx/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    # Only over authenticated API possible
    if (concluded = get_kb_item("vmware/nsx/http-api/" + port + "/concluded"))
      extra += '  Concluded from version/product identification result (HTTP API): ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (ssh_ports = get_kb_list("vmware/nsx/ssh-login/port")) {
  foreach port (ssh_ports) {
    extra += 'SSH login on port ' + port + '/tcp\n';

    concluded = get_kb_item("vmware/nsx/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report = build_detection_report(app: "VMware NSX", version: detected_version, build: detected_build,
                                install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
