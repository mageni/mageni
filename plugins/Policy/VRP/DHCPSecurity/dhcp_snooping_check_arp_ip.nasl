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
  script_oid("1.3.6.1.4.1.25623.1.0.150296");
  script_version("2020-10-06T07:40:27+0000");
  script_tag(name:"last_modification", value:"2020-10-07 09:36:44 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-07-14 07:39:50 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Configuring IP/MAC Spoofing Attack Packet Check");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("vrp_current_configuration.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"To prevent man-in-the-middle attacks and IP/MAC spoofing attacks,
you can enable the function of checking packets on the device. Checks whether the source IP address
and source MAC address in a received ARP or IP packet match those in the DHCP snooping binding table.");

  exit(0);
}

include("policy_functions.inc");

major_version = get_kb_item("huawei/vrp/ssh-login/major_version");

cmd = "display current-configuration";
title = "Configuring IP/MAC Spoofing Attack Packet Check";
solution = "When man-in-the-middle attacks and IP/MAC spoofing attacks occur, configure ARP and IP
packet check to check whether the source IP address and source MAC address in ARP or IP packets
match the DHCP snooping binding table.";
test_type = "SSH_Cmd";
default = "Enabled";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(!major_version){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine version of VRP device.";
}else if(major_version !~ "^8"){ # nb: Test applies for VRP V8 devices only
  # Don't report result if not applicable.
  exit(0);
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/current_configuration/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the current configuration.";
}else{
  current_configuration = get_kb_item("Policy/vrp/current_configuration");
  if(current_configuration =~ "dhcp\s+snooping\s+check\s+arp\s+enable"){
    comment += ", ARP enabled";
    value = "Enabled";
  }

  if(current_configuration =~ "dhcp\s+snooping\s+check\s+ip\s+enable"){
    comment += ", IP enabled";
    value = "Enabled";
  }

  if(!value)
    value = "Disabled";

  compliant = policy_setting_exact_match(value:value, set_point:default);

  if(comment)
    comment = str_replace(string:comment, find:", ", replace:"", count:1);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
