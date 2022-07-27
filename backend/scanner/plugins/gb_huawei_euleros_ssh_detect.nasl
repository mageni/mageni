# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_version("2020-01-16T09:51:04+0000");
  script_tag(name:"last_modification", value:"2020-01-16 09:51:04 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-14 10:04:36 +0000 (Tue, 14 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Huawei EulerOS Detection (SSH)");

  script_tag(name:"summary", value:"Detection of Huawei EulerOS.

  This script performs SSH based detection of Huawei EulerOS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("euleros/ssh_login/port");

  exit(0);
}

if (!port = get_kb_item("euleros/ssh-login/port"))
  exit(0);

set_kb_item(name: "huawei/euleros/detected", value: TRUE);
set_kb_item(name: "huawei/euleros/ssh-login/port", value: port);

version = "unknown";

rls = get_kb_item("euleros/ssh-login/" + port + "/rls");

# EulerOS release 2.0
# EulerOS release 2.0 (SP2)
vers = eregmatch(pattern: "^EulerOS release ([0-9]+\.[0-9]+)( \(SP([0-9]+)\))?", string: rls, icase: TRUE);

if (!isnull(vers[1])) {
  set_kb_item(name: "huawei/euleros/ssh-login/" + port + "/version", value: vers[1]);

  if (!isnull(vers[3])) {
    set_kb_item(name: "huawei/euleros/ssh-login/" + port + "/sp", value: vers[3]);
  } else {
    set_kb_item(name: "huawei/euleros/ssh-login/" + port + "/sp", value: "0");
  }

  set_kb_item(name: "huawei/euleros/ssh-login/" + port + "/concluded", value: rls);
}

exit(0);
