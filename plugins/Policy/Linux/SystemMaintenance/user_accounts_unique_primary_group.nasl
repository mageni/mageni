# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150140");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-02-19 14:23:22 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Unique primary groups for user accounts");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_passwd_file.nasl", "kb_set_uid_min_max.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/");

  script_tag(name:"summary", value:"The password file stores information about users such like
username, UID, GID, etc.

Users with same group can access and unintentionally or maliciously modify another user's files.");

  exit(0);
}

include("policy_functions.inc");

cmd = 'egrep -v "^\\+" /etc/passwd | awk -F: \'($3>500) {print}\'';
title = "Unique primary groups for user accounts";
solution = "Change the users primary group";
test_type = "SSH_Cmd";
default = "None";

if(get_kb_item("Policy/linux//etc/login.defs/ERROR") || get_kb_item("Policy/linux//etc/passwd/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to the host";
}else if(get_kb_item("Policy/linux//etc/login.defs/content/ERROR") || get_kb_item("Policy/linux//etc/passwd/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/login.defs or /etc/passwd";
}else{
  if(!uid_min = get_kb_item("Policy/linux//etc/login.defs/UID_MIN"))
    uid_min = 500;

  gids_array = make_array();
  content = get_kb_item("Policy/linux//etc/passwd/content");
  foreach line (split(content, keep:FALSE)){
    fields = split(line, sep:":", keep:FALSE);
    if(int(fields[2]) < int(uid_min))
      continue;

    user_name = fields[0];
    gid = fields[3];

    if(gids_array[gid]){
      value += ", " + gid + ": " + user_name + " " + gids_array[gid];
    }else{
      gids_array[gid] = user_name;
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
