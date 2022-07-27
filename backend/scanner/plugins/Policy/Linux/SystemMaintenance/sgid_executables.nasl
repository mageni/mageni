# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109822");
  script_version("2020-07-29T07:27:10+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-03-18 11:05:45 +0100 (Mon, 18 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SGID files");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_add_preference(name:"Files with SGID", type:"entry", value:"", id:1);

  script_xref(name:"URL", value:"https://linoxide.com/how-tos/stickbit-suid-guid/");

  script_tag(name:"summary", value:"When the SGID (set group ID) bit is set on an executable, it
executes with the GID of the owner. This may be intended for some executables. Add files with SGID
bit which should be allowed to have this bit set in the preference.

This script checks if any other local files than the given have the SGID bit set.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "df --local --output='target' | xargs -I '{}' find '{}' -xdev -type f -perm -2000";
title = "SGID executables";
solution = "Remove SGID bit from file";
test_type = "SSH_Cmd";
default = script_get_preference("Files with SGID", id:1);
comment = "";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection";
}else{
  compliant = "yes";
  cmd = 'df --local --output="target" | grep \'/\' | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -2000 2>/dev/null';
  files = ssh_cmd(cmd:cmd, socket:sock);
  if(files){
    files_list = split(files, keep:FALSE);
    foreach file (files_list){
      value += ";" + file;
      if(chomp(file) >!< default){
        compliant = "no";
      }
    }
  }

  if(value)
    value = str_replace(string:value, find:';', replace:'', count:1);
  else
    value = "None";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);