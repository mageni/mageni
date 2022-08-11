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
  script_oid("1.3.6.1.4.1.25623.1.0.145271");
  script_version("2021-02-01T14:29:13+0000");
  script_tag(name:"last_modification", value:"2021-02-02 11:22:57 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-01-28 08:56:42 +0000 (Thu, 28 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Huawei FusionSphere OpenStack Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Huawei FusionSphere OpenStack.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/euleros/is_uvp", "huawei/euleros/ssh-login/port");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: "cpe:/o:huawei:euleros_virtualization", service: "ssh-login"))
  exit(0);

port = infos["port"];

soc = ssh_login_or_reuse_connection();
if (!soc)
  exit(0);

# {"install_type": "openstack", "install_info": {"os": [{"platform": "x86_64", "default_os": "true", "version": "2.0", "type": "euleros"}]}, "solution_scenes": "NFVI"
# Where NFVI are FusionSphere OpenStack installations
file = "/opt/fusionplatform/data/fusionsphere/cfg/install-data.cfg";
install_data = ssh_cmd(socket: soc, cmd: "cat " + file);
if (install_data !~ '"solution_scenes"\\s*:\\s*"NFVI"') {
  close(soc);
  exit(0);
}

conclloc = "  - " + file;
concl = "  - " + install_data;

file = "/etc/hostos.version";
hostos = ssh_cmd(socket: soc, cmd: "cat " + file);
close(soc);

version = "unknown";

set_kb_item(name: "huawei/fusionsphere_openstack/detected", value: TRUE);
set_kb_item(name: "huawei/fusionsphere_openstack/ssh-login/port", value: port);

# FUSIONSPHERE FUSIONPLATFORM 8.0.0.SPC17
vers = eregmatch(pattern: 'FUSIONSPHERE FUSIONPLATFORM ([^\r\n]+)', string: hostos);
if (!isnull(vers[1])) {
  conclloc += '\n  - ' + file;
  concl += '\n  - ' + vers[0];
  version = vers[1];
}

set_kb_item(name: "huawei/fusionsphere_openstack/ssh-login/" + port + "/concluded", value: concl);
set_kb_item(name: "huawei/fusionsphere_openstack/ssh-login/" + port + "/concluded_loc", value: conclloc);
set_kb_item(name: "huawei/fusionsphere_openstack/ssh-login/" + port + "/version", value: version);

exit(0);
