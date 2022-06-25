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
  script_oid("1.3.6.1.4.1.25623.1.0.109765");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-01-24 14:44:53 +0100 (Thu, 24 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Accept IPv6 router advertisements");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_and_parse_sysctl.nasl", "read_etc_sysctl_d.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Status", type:"radio", value:"Disabled;Enabled");

  script_tag(name:"summary", value:"To set up its default route and choose an IPv6 address, a Linux
system requests and listen for router advertisements. Router advertisements can be used to route
traffic to compromised systems.
This script tests whether the Linux host is configured to accept IPv6 router advertisements.");

  exit(0);
}

include("policy_functions.inc");

cmd = "sysctl net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra";
title = "IPv6 router advertisements";
solution = "sysctl -w net.ipv6.conf.all.accept_ra=[0,1], sysctl -w net.ipv6.conf.default.accept_ra=[0,1]";
test_type = "SSH_Cmd";
default = script_get_preference("Status", id:1);

if(get_kb_item("Policy/linux/sysctl/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux/sysctl/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run sysctl";
}else{
  net_ipv6_conf_all_accept_ra = get_kb_item("Policy/linux/sysctl/net.ipv6.conf.all.accept_ra");
  net_ipv6_conf_default_accept_ra = get_kb_item("Policy/linux/sysctl/net.ipv6.conf.default.accept_ra");

  if(net_ipv6_conf_all_accept_ra == "0" && net_ipv6_conf_default_accept_ra == "0")
    value = "Disabled";
  else
    value = "Enabled";

  compliant = policy_setting_exact_match(value:value, set_point:default);

  if(get_kb_item("Policy/linux//etc/sysctl.conf/content/ERROR")){
    comment = "Can not read file /etc/sysctl.conf";
  }else{
    sysctl_content = get_kb_item("Policy/linux//etc/sysctl.conf/content");
    grep = egrep(string:sysctl_content, pattern:"(net.ipv6.conf.all.accept_ra|net.ipv6.conf.default.accept_ra)");
    if(grep)
      comment = "Setting in /etc/sysctl.conf: " + chomp(grep);
    else
      comment = "Can not find setting in /etc/sysctl.conf";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);