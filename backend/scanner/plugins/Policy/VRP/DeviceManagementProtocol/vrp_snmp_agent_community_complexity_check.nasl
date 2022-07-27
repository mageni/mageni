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
  script_oid("1.3.6.1.4.1.25623.1.0.150249");
  script_version("2020-10-06T07:40:27+0000");
  script_tag(name:"last_modification", value:"2020-10-07 09:36:44 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-05-14 07:32:07 +0000 (Thu, 14 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: SNMP agent complexity-check");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("vrp_current_configuration_snmp.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"If SNMPv1 and SNMPv2 are used, the community complexity check
function must be enabled.");

  exit(0);
}

include("policy_functions.inc");

port = get_kb_item("huawei/vrp/ssh-login/port");
model = get_kb_item("huawei/vrp/ssh-login/" + port + "/model");
major_version = get_kb_item("huawei/vrp/ssh-login/major_version");

if(major_version =~ "^8")
  cmd = "display snmp-agent sys-info version; display current-configuration | include snmp";
else
  cmd = "display current-configuration | include snmp";

title = "Configure community name complexity check";
solution = "Run the undo snmp-agent community complexity-check disable command to enable the
complexity check function for community names.";
test_type = "SSH_Cmd";
default = "Enable";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(!model || !major_version){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine model or version of VRP device.";
}else if(model =~ "^AR" && major_version =~ "^5"){ # nb: Test doesn't apply to AR devices on VRP V5
  # Don't report anything if test not applicable
  exit(0);
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/current_configuration/snmp/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the current SNMP configuration.";
}else if(!sys_info_version = get_kb_item("Policy/vrp/snmp_agent_version")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the snmp-agent sys-info version.";
}else if(sys_info_version !~ "(SNMPv1|SNMPv2c|SNMPv1|SNMPv2|v1|v2c|all)"){
  value = "SNMP agent version: " + sys_info_version;
  compliant = "yes";
  comment = "SNMP agent version not matching SNMPv1, SNMPv2c, SNMPv1, SNMPv2, v1, v2c or all";
}else{
  snmp = get_kb_item("Policy/vrp/current_configuration/snmp");
  if(snmp =~ "snmp-agent\s+community\s+complexity-check\s+disable" &&
     snmp !~ "undo\s+snmp-agent\s+community\s+complexity-check\s+disable"){
    value = "Disable";
    compliant = "no";
    comment = "SNMP v1 or v2 enabled, complexity check for community names disabled.";
  }else{
    value = "Enable";
    compliant = "yes";
    comment = "SNMP v1 or v2 enabled, complexity check for community names enabled.";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
