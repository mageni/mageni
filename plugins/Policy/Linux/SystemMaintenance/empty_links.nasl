# Copyright (C) 2020 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150098");
  script_version("2020-07-29T07:27:10+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-01-22 14:30:08 +0100 (Wed, 22 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Empty links");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/1/ln");

  script_tag(name:"summary", value:"Links point to another file or directory.

This script checks if any empty link exists on the host.

Note: This script dramatically increases the scan duration.
Note: Exclude directories */proc, /run, /dev, /sys, /media, /tmp and /var");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "find -L / \( -path */proc -o -path /run -o -path /dev -o -path /sys -o -path /media -o -path /tmp -o -path /var \) -prune -o -type l -print";
title = "Empty links";
solution = "Remove empty link";
test_type = "SSH_Cmd";
default = "None";
comment = "";
value = "None";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection";
}else{
  compliant = "yes";
  ssh_cmd = cmd + " 2>/dev/null";
  files = ssh_cmd(cmd:cmd, socket:sock);
  if(files){
    compliant = "no";
    files_list = split(files, keep:FALSE);
    value = policy_build_string_from_list(list:files_list, sep:",");
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);