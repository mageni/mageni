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
  script_oid("1.3.6.1.4.1.25623.1.0.109801");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-03-05 10:39:40 +0100 (Tue, 05 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Disable account when password expires");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_default_useradd.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Days", type:"entry", value:"30", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/8/useradd");

  script_tag(name:"summary", value:"A user without activity can be locked after a specific period of
time. When creating a new user with 'useradd', the number of days until the account is permanently
disabled after a password expires can be specified.

This script checks the 'INACTIVE' default parameter in /etc/default/useradd.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep '^INACTIVE' /etc/default/useradd";
title = "Account validity period";
solution = "Edit /etc/default/useradd";
test_type = "SSH_Cmd";
default = script_get_preference("Days", id:1);

if(get_kb_item("Policy/linux//etc/default/useradd/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/default/useradd";
}else{
  content = get_kb_item("Policy/linux//etc/default/useradd/content");
  foreach line (split(content, keep:FALSE)){
    match = eregmatch(string:line, pattern:"^\s*INACTIVE\s*=\s*([0-9]*)");
    if(match)
      value = policy_return_greater_value(value1:value, value2:match[1]);
  }

  compliant =  policy_setting_max_match(value:value, set_point:default);
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);