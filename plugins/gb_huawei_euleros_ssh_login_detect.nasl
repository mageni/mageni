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
  script_oid("1.3.6.1.4.1.25623.1.0.143354");
  script_version("2021-07-13T13:08:53+0000");
  script_tag(name:"last_modification", value:"2021-07-14 10:38:42 +0000 (Wed, 14 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-14 10:04:36 +0000 (Tue, 14 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Huawei EulerOS Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Huawei EulerOS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/euleros/port");

  exit(0);
}

if (!port = get_kb_item("ssh/login/euleros/port"))
  exit(0);

set_kb_item(name: "huawei/euleros/detected", value: TRUE);
set_kb_item(name: "huawei/euleros/ssh-login/port", value: port);

version = "unknown";

euleros_rls = get_kb_item("ssh/login/euleros/" + port + "/euleros_release");

# EulerOS release 2.0
# EulerOS release 2.0 (SP2)
# EulerOS release 2.0 (SP5)
# EulerOS release 2.0 (SP9x86_64)
# EulerOS release 2.0 (SP9) -> This could be aarch64
vers = eregmatch(pattern: "^EulerOS release ([0-9]+\.[0-9]+)( \(SP([0-9]+)(x86_64)?\))?", string: euleros_rls, icase: TRUE);
if (!isnull(vers[1])) {

  concluded = vers[0];
  concluded_location = "/etc/euleros-release";

  uvp_rls = get_kb_item("ssh/login/euleros/" + port + "/uvp_release");
  if (uvp_rls) {
    # EulerOS Virtualization release 3.0.2.1 (x86_64)
    # nb: There is also "EulerOS Virtualization for ARM 64" but the release string of this is currently unknown.
    vers = eregmatch(pattern: "^EulerOS Virtualization.+release ([0-9.]+)", string: uvp_rls, icase: TRUE);
    if (!isnull(vers[1])) {
      concluded = '\n  - UVP:         ' + vers[0] + '\n' + "  - Base-System: " + concluded;
      concluded_location = '\n  - UVP:         /etc/uvp-release\n' + "  - Base-System: " + concluded_location;
    }
  } else {
    if (!isnull(vers[3])) {
      set_kb_item(name: "huawei/euleros/ssh-login/" + port + "/sp", value: vers[3]);
    } else {
      set_kb_item(name: "huawei/euleros/ssh-login/" + port + "/sp", value: "0");
    }

    # nb: Starting with EulerOS 2.0 SP9 (see examples above) the euleros-release contains the
    # x86_64 which needs to be appended to the oskey saved into ssh/login/release within
    # gb_huawei_euleros_consolidation.nasl.
    if (!isnull(vers[4]))
      set_kb_item(name: "huawei/euleros/ssh-login/oskey_addition", value: vers[4]);

  }

  set_kb_item(name: "huawei/euleros/ssh-login/" + port + "/version", value: vers[1]);
  set_kb_item(name: "huawei/euleros/ssh-login/" + port + "/concluded", value: concluded);
  set_kb_item(name: "huawei/euleros/ssh-login/" + port + "/concluded_location", value: concluded_location);
}

exit(0);