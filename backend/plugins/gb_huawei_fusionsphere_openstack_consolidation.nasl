# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145272");
  script_version("2021-02-01T14:29:13+0000");
  script_tag(name:"last_modification", value:"2021-02-02 11:22:57 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-01-28 09:57:37 +0000 (Thu, 28 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei FusionSphere OpenStack Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Huawei FusionSphere OpenStack detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_huawei_fusionsphere_openstack_ssh_login_detect.nasl");
  script_mandatory_keys("huawei/fusionsphere_openstack/detected");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/cloud-computing/fusionsphere-openstack-pid-21100528");

  exit(0);
}

if (!get_kb_item("huawei/fusionsphere_openstack/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login")) {
  version_list = get_kb_list("huawei/fusionsphere_openstack/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9spch.]+)", base: "cpe:/a:huawei:fusionsphere_openstack:");
if (!cpe)
  cpe = "cpe:/a:huawei:fusionsphere_openstack";

if (ssh_login_ports = get_kb_list("huawei/fusionsphere_openstack/ssh-login/port")) {
  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    extra += '  Port: ' + port + '/tcp\n';
    concluded = get_kb_item("huawei/fusionsphere_openstack/ssh-login/" + port + "/concluded");
    concloc = get_kb_item("huawei/fusionsphere_openstack/ssh-login/" + port + "/concluded_loc");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    if (concloc)
      extra += '  Concluded from version/product identification location:\n' + concloc + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report = build_detection_report(app: "Huawei FusionSphere OpenStack", version: detected_version,
                                install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
