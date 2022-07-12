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
  script_oid("1.3.6.1.4.1.25623.1.0.109735");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-01-09 08:27:44 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Restricted core dumps");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_security_limits.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Status", type:"radio", value:"Enabled;Disabled", id:1);

  script_xref(name:"URL", value:"https://www.cyberciti.biz/faq/linux-disable-core-dumps/");

  script_tag(name:"summary", value:"Core dumps are the memory of a process when it crashes. Core
dumps can grow to significant size, ending in a Denial of Service. Also, core dumps can be used to
get confidential information from a core file.

Note: This scripts looks for '* hard core 0' setting in /etc/security/limits.conf file and *.conf files in the
/etc/security/limits.d directory.");
  exit(0);
}

include("policy_functions.inc");

cmd = "grep 'hard core' /etc/security/limits.conf /etc/security/limits.d/*";
title = "Restricted core dumps (pam_limits config)";
solution = "Add '* hard core 0' to /etc/security/limits.conf or a /etc/security/limits.d/* file";
test_type = "SSH_Cmd";
default = script_get_preference("Status", id:1);

if(get_kb_item("Policy/linux/security/limits/conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/security/limits.conf/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/security/limits.conf";
}else{
  content = get_kb_item("Policy/linux//etc/security/limits.conf/content");
  if(content =~ "\*\s+hard\s+core\s+0")
    value = "Enabled";

  foreach file (get_kb_list("Policy/linux//etc/security/limits.d//files/*")){
    content = get_kb_item("Policy/linux/" + file + "/content");
    if(content =~ "\*\s+hard\s+core\s+0")
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