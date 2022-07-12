# Copyright (C) 2019 Greenbone Networks GmbH
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.109833");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-03-26 08:11:19 +0100 (Tue, 26 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Duplicated GIDs");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_group.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/5/group");

  script_tag(name:"summary", value:"Duplicated GIDs can occur after modifiying '/etc/group'. Groups
with same GIDs are not only granted same privileges, but they are considered as the same group.

This script tests if any duplicated GIDs are listed in '/etc/group'.");

  exit(0);
}

include("policy_functions.inc");

cmd = "cat /etc/group | cut -d: -f1,3";
title = "No duplicated GIDs";
solution = "Modify GIDs for users with duplicated GID.";
test_type = "SSH_Cmd";
default = "None";

if(get_kb_item("Policy/linux//etc/group/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/group/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/group";
}else{
  gids_array = make_array();
  content = get_kb_item("Policy/linux//etc/passwd/content");
  foreach line (split(content, keep:FALSE)){
    fields = split(line, sep:":", keep:FALSE);
    group_name = fields[0];
    gid = fields[2];
    if(gids_array[gid]){
      value += ", " + gid + ": " + group_name + " " + gids_array[gid];
    }else{
      gids_array[gid] = group_name;
    }
  }

  if(value){
    value = str_replace(string:value, find:", ", replace:"", count:1);
    compliant = "no";
  }else{
    value = "None";
    compliant = "yes";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);