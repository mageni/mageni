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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148475");
  script_version("2022-07-20T02:04:50+0000");
  script_tag(name:"last_modification", value:"2022-07-20 02:04:50 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-19 03:46:27 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Huawei EulerOS: Gather Applied HotFix (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros");

  script_tag(name:"summary", value:"Gathers information about applied HotFixes/Livepatches for
  EulerOS via the provided 'Get-HotFix' tool.");

  exit(0);
}

include("ssh_func.inc");

soc = ssh_login_or_reuse_connection();
if (!soc)
  exit(0);

port = kb_ssh_transport();

hotfix_bin = "/usr/bin/Get-HotFix";

hotfix = ssh_cmd(socket: soc, cmd: hotfix_bin);
if (hotfix) {
  set_kb_item(name: "euleros/get_hotfix", value: hotfix);
  set_kb_item(name: "euleros/get_hotfix/port", value: port);
}

ssh_close_connection();

exit(0);
