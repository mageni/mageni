# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150265");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-09 15:01:00 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Blacklisted Services");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_and_parse_running_services.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Blacklist", type:"entry", value:"service1,service2", id:1);

  script_tag(name:"summary", value:"Some services have security issues or should not be running on
the host for other reasons.

This script checks if any of the given services is running on the host by using systemctl.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "systemctl --state=running";
title = "Blacklisted services";
solution = "Disable service";
test_type = "SSH_Cmd";
default = script_get_preference("Blacklist", id:1);

if(get_kb_item("Policy/linux/systemctl/running/ssh/ERROR")) {
  value = "Error";
  compliant = "incomplete";
  note = "No SSH connection possible";
} else if(get_kb_item("Policy/linux/systemctl/running/ERROR")) {
  value = "Error";
  compliant = "incomplete";
  note = "can not detect running services";
} else {
  running_services = get_kb_list("Policy/linux/systemctl/running");

  default_list = policy_build_list_from_string(str:default);
  foreach service(default_list){
    if(service >< running_services){
      value += "," + service;
    }
  }

  if(value) {
    value = str_replace(string:value, find:",", replace:"", count:1);
    compliant = "no";
  } else {
    compliant = "yes";
    value = "None";
  }
  note = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:note);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);