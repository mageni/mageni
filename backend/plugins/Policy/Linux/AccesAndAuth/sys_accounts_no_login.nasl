# Copyright (C) 2019 Greenbone Networks GmbH
#
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.109802");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-03-11 09:27:01 +0100 (Mon, 11 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Deny login for system accounts");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("kb_set_uid_min_max.nasl", "read_passwd_file.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/");

  script_tag(name:"summary", value:"System account are used to manage applications. They are not
linked with a natural person and thus do not need an interactive shell. To prevent system accounts
to run any commands, the shell field in '/etc/passwd' can e.g. be set to '/sbin/nologin'.

This script tests, if any system account provides an interactive shell.");
  exit(0);
}

include("policy_functions.inc");

cmd = 'egrep -v "^\\+" /etc/passwd | awk -F: \'($1!="root" && $1!="sync" && $1!="shutdown" ';
cmd += '&& $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false") {print}\'';
title = "Deny login for system accounts";
solution = "usermod -s /sbin/nologin SYSTEM_ACCOUNT";
test_type = "SSH_Cmd";
default = "None";

if(get_kb_item("Policy/linux//etc/login.defs/ERROR") || get_kb_item("Policy/linux//etc/passwd/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/login.defs or /etc/passwd";
}else{
  if(!max = get_kb_item("Policy/linux//etc/login.defs/SYS_UID_MAX")){
    if(uid_min = get_kb_item("Policy/linux//etc/login.defs/UID_MIN")){
      max = int(uid_min) - 1;
    }else{
      max = "999";
    }
  }
  content = get_kb_item("Policy/linux//etc/passwd/content");
  foreach line (split(content, keep:FALSE)){
    fields = split(line, sep:":", keep:FALSE);
    if(fields[0] =~ "^(root|sync|shutdown|halt)$" || int(fields[2]) > int(max))
      continue;

    if(fields[6] !~ "^(/sbin/nologin|/bin/false)$")
      value += ", " + fields[0];
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
