# Copyright (C) 2020 Greenbone Networks GmbH
#
# Text descriptions are largely excerpted from the referenced
# website, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.150174");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-03-18 14:56:05 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: server or pool in /etc/ntp.conf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_ntp_conf.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_add_preference(name:"Value", type:"entry", value:"ip1,ip2", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/8/selinux");

  script_tag(name:"summary", value:"For type s and r addresses (only), this command normally
mobilizes a persistent client mode association with the specified remote server or local reference
clock. If the preempt flag is specified, a preemptible association is mobilized instead. In client
mode the client clock can synchronize to the remote server or local reference clock, but the remote
server can never be synchronized to the client clock. This command should NOT be used for type b or
m addresses.");

  exit(0);
}

include("policy_functions.inc");

cmd = " grep -E '^(server|pool)' /etc/ntp.conf";
title = "Synchronize clock from a trusted and precise time source";
solution = "Add 'server SERVER' to /etc/ntp.conf";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux//etc/ntp.conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/ntp.conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/ntp.conf";
}else{
  content = get_kb_item("Policy/linux//etc/ntp.conf/content");
  grep = egrep(string:content, pattern:"(pool|server)");

  foreach line (split(grep)){
    if(line =~ "^\s*#")
      continue;

    match = eregmatch(string:chomp(line), pattern:"(pool|server)\s+([a-z,A-Z,0-9,.]+)");
    if(match)
      value += "," + match[2];
  }

  if(!value)
    value = "None";
  else
    value = str_replace(string:value, find:",", replace:"", count:1);

  compliant = policy_settings_lists_match(value:value, set_points:default, sep:",");
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
