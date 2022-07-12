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
  script_oid("1.3.6.1.4.1.25623.1.0.109762");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-01-24 07:47:12 +0100 (Thu, 24 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Log non-standard ICMP messages");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_sysctl_d.nasl", "read_and_parse_sysctl.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Status", type:"radio", value:"Enabled;Disabled", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sysctl.conf");
  script_xref(name:"URL", value:"https://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/");

  script_tag(name:"summary", value:"To reduce logfile size, it is possible to ignore ICMP messages
that do not match standards.

This script tests whether the Linux host is configured to ignore non-standard ICMP messages.");

  exit(0);
}

include("policy_functions.inc");

cmd = "sysctl net.ipv4.icmp_ignore_bogus_error_responses";
title = "Ignore bogus ICMP responses";
solution = "sysctl -w net.ipv4.icmp_ignore_bogus_error_responses = [0,1]";
test_type = "SSH_Cmd";
default = script_get_preference("Status", id:1);

if(get_kb_item("Policy/linux/sysctl/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux/sysctl/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run sysctl command";
}else{
  # sysctl -a output
  net_ipv4_icmp_ignore_bogus_error_responses = get_kb_item("Policy/linux/sysctl/net.ipv4.icmp_ignore_bogus_error_responses");

  if(!net_ipv4_icmp_ignore_bogus_error_responses){
    value = "Error";
    compliant = "incomplete";
    comment = "Could not find setting with sysctl";
  }else{
    if(net_ipv4_icmp_ignore_bogus_error_responses == "1")
      value = "Disabled";
    else
      value = "Enabled";
    compliant = policy_setting_exact_match(value:value, set_point:default);
  }

  if(get_kb_item("Policy/linux/sysctl/conf/ERROR")){
    comment = "No SSH connection to host to read /etc/sysctl config files.";
  }else{
    files = make_list("/etc/sysctl.conf", get_kb_list("Policy/linux//etc/sysctl.d//files/"));
    foreach file (files){
      if(get_kb_item("Policy/linux/" + file + "/content/ERROR"))
        continue;

      content = get_kb_item("Policy/linux/" + file + "/content");

      grep_pattern = egrep(string:content, pattern:"net.ipv4.icmp_ignore_bogus_error_responses");
      if(grep_pattern){
        grep_pattern = str_replace(string:grep_pattern, find:'\r\n', replace:" ");
        comment += ', ' + file + ": " + chomp(grep_pattern);
      }
    }

    if(comment)
      comment = str_replace(string:comment, find:', ', replace:"", count:1);
    else
      comment = "Could not find setting in any sysctl config file";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);