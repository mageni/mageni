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
  script_oid("1.3.6.1.4.1.25623.1.0.150057");
  script_version("2020-01-15T07:08:19+0000");
  script_tag(name:"last_modification", value:"2020-01-15 07:08:19 +0000 (Wed, 15 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 15:36:48 +0100 (Thu, 09 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: list mounted filesystems");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"All files accessible in a Unix system are arranged in one big
tree, the file hierarchy, rooted at /. These files can be spread out over several devices.

Note: This script only stores information for other Policy Controls.");
  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success")){
  set_kb_item(name:"linux/mount/ERROR", value:TRUE);
  exit(0);
}

sock = ssh_login_or_reuse_connection();
if(!sock){
  set_kb_item(name:"linux/mount/ERROR", value:TRUE);
  exit(0);
}

cmd = "mount -l";
ret = ssh_cmd_without_errors(socket:sock, cmd:cmd);
if(!ret){
  set_kb_item(name:"linux/mount/ERROR", value:TRUE);
  exit(0);
}

ret_split = split(ret, keep:FALSE);
foreach line (ret_split){
  reg_match = eregmatch(string:line, pattern:"(.+) on (.+) type (.+) \((.+)\)");

  if(!reg_match)
    continue;

  device = reg_match[2];
  type = reg_match[3];
  options = reg_match[4];

  set_kb_item(name:"linux/mount/device", value:device);
  set_kb_item(name:"linux/mount/" + device + "/type", value:type);
  set_kb_item(name:"linux/mount/" + device + "/options", value:options);
}

exit(0);