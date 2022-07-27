# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150235");
  script_version("2020-10-06T07:40:27+0000");
  script_tag(name:"last_modification", value:"2020-10-07 09:36:44 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-05-13 09:49:46 +0000 (Wed, 13 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: VTY authentication security check");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("vrp_current_configuration_user_interface.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"The VTY authentication mode is insecure if the password
authentication mode is configured.");

  exit(0);
}

include("policy_functions.inc");

cmd = "display current-configuration configuration user-interface";
title = "VTY authentication security check";
solution = "Configure AAA.";
test_type = "SSH_Cmd";
default = "All vty user-interfaces have authentication-mode aaa enabled.";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/current_configuration/user_interface/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the current user-interface configuration.";
}else{
  kb_interfaces = get_kb_item("Policy/vrp/current_configuration/user_interface");
  interfaces = split(kb_interfaces, sep:"user-interface", keep:TRUE);
  foreach interface (interfaces){
    if(interface =~ "^\s*vty [0-9]"){
      if(interface !~ "authentication-mode aaa"){
        compliant = "no";
        value = "Not all vty-interfaces have authentication-mode aaa enabled";
      }
    }
  }

  if(!value){
    value = "All vty user-interfaces have authentication-mode aaa enabled.";
    compliant = "yes";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
