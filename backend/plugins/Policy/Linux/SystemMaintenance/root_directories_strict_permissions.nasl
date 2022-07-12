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
  script_oid("1.3.6.1.4.1.25623.1.0.150109");
  script_version("2020-07-29T07:27:10+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 10:27:51 +0100 (Wed, 29 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Strict permissions for directories owned by root");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_gnu_bash_detect_lin.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://wiki.debian.org/Permissions");

  script_add_preference(name:"Whitelist", type:"entry", value:"", id:1);

  script_tag(name:"summary", value:"This script searches for directories owned by root user with
another group or access permissions stricter then 755.

Note: This script dramatically increases the scan duration.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "find / -type d -user root \( -perm 777 -o -perm 757 -o -not -group root \)";
title = "Strict permissions for directories owned by root";
solution = "chown root:root DIR, chmod PERMISSIONS DIR";
test_type = "SSH_Cmd";
default = script_get_preference("Whitelist", id:1);
compliant = "yes";
value = "None";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection";
}else if (!get_kb_item("bash/linux/detected")){
  value = "Error";
  compliant = "incomplete";
  comment = "Bash is not available on the target host but needed for this test.";
}else{
  ssh_cmd = cmd + " 2>/dev/null";
  files = ssh_cmd(cmd:ssh_cmd, socket:sock, nosh:TRUE);
  if(files){
    value = str_replace(string:files, find:'\r\n', replace:",");
    foreach file (split(files, keep:FALSE)){
      if(file >< default){
        continue;
      }
      compliant = "no";
    }
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);