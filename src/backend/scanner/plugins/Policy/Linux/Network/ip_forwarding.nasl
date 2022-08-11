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
  script_oid("1.3.6.1.4.1.25623.1.0.109755");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-01-24 08:47:05 +0100 (Thu, 24 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: IP Forwarding");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_sysctl_d.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Status", type:"radio", value:"Disabled;Enabled", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sysctl.conf");
  script_xref(name:"URL", value:"https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux");

  script_tag(name:"summary", value:"IP forwarding is used to determine which path a packet can be
sent over multiple networks. The 'net.ipv4.ip_forward' parameter on Linux systems is used to
determine whether the system can forward packets.

Note: This scripts looks for 'net.ipv4.ip_forward=0' setting in /etc/sysctl.conf file and files in
/etc/sysctl.d/ directory.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep 'net.ipv4.ip_forward' /etc/sysctl.conf /etc/sysctl.d/*";
title = "IP Forwarding";
solution = "Add or remove 'net.ipv4.ip_forward = 0' to /etc/sysctl.conf or a /etc/sysctl.d/* file";
test_type = "SSH_Cmd";
default = script_get_preference("Status", id:1);

if(get_kb_item("Policy/linux/sysctl/conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/sysctl.conf/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/sysctl.conf";
}else{
  content = get_kb_item("Policy/linux//etc/sysctl.conf/content");
  if(content =~ "net.ipv4.ip_forward\s*=\s*0")
    value = "Enabled";

  foreach file (get_kb_list("Policy/linux//etc/sysctl.d//files/*")){
    content = get_kb_item("Policy/linux/" + file + "/content");
    if(content =~ "net.ipv4.ip_forward\s*=\s*0")
      value = "Enabled";
  }

  if(!value)
    value = "Disabled";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);