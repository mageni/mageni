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
  script_oid("1.3.6.1.4.1.25623.1.0.150258");
  script_version("2020-10-06T07:40:27+0000");
  script_tag(name:"last_modification", value:"2020-10-07 09:36:44 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-05-15 12:08:01 +0000 (Fri, 15 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Configuring ARP Packet Rate Limiting");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("vrp_current_configuration.nasl", "vrp_display_arp_speed_limit.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"After the rate limit for ARP packets is configured, the device counts
the number of ARP packets. If the number of ARP packets exceeds the configured threshold
within a certain period, the device does not process the excess ARP packets.");

  exit(0);
}

include("policy_functions.inc");

title = "Configuring ARP Packet Rate Limiting";
solution = "By default, the rate limit based on the source IP address is 30. In an insecure
environment, you can reduce the rate limit to reduce the rate of processing ARP packets.";
test_type = "SSH_Cmd";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(!major_version = get_kb_item("huawei/vrp/ssh-login/major_version")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine version of device.";
}else if(major_version =~ "^8"){
  # v8 devices

  cmd = "display arp speed-limit";
  default_sourceip = "100";
  default_destinationip = "500";
  default = "Source-ip >= " + default_sourceip + ", Destination-ip >= " + default_destinationip;

  if(get_kb_item("Policy/vrp/arp/speedlimit/ERROR")){
    value = "Error";
    compliant = "incomplete";
    comment = "Can not determine the current arp speed-limit configuration.";
  }else{
    slots = get_kb_list("Policy/vrp/arp/speedlimit/slots");
    foreach slot (slots){
      sourceip = get_kb_item("Policy/vrp/arp/speedlimit/" + slot + "/sourceip");
      destinationip = get_kb_item("Policy/vrp/arp/speedlimit/" + slot + "/destinationip");
      if(policy_setting_min_match(value:sourceip, set_point:default_sourceip) == "no" ||
        policy_setting_min_match(value:destinationip, set_point:default_destinationip) == "no"){
        value = "Source-ip not >= " + default_sourceip + " or Destination-ip not >= " + default_destinationip;
        compliant = "no";
      }
    }

    if(!value){
      value = "Source-ip >= " + default_sourceip + ", Destination-ip >= " + default_destinationip;
      compliant = "yes";
    }
  }
}else{
  # V5 devices

  default = "30";
  cmd = "display current-configuration";

  if(get_kb_item("Policy/vrp/current_configuration/ERROR")){
    value = "Error";
    compliant = "incomplete";
    comment = "Can not determine the current arp configuration.";
  }else{
    vrp_configuration = get_kb_item("Policy/vrp/current_configuration");
    arp_max = eregmatch(string:vrp_configuration, pattern:"arp\s+speed-limit\s+source-ip\s+[0-9.\s]*maximum\s+([0-9]+)");
    if(arp_max)
      value = arp_max[1];
    else
      value = "None";

    compliant = policy_setting_min_match(value:value, set_point:default);
  }
  default = ">= " + default;
}


policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
