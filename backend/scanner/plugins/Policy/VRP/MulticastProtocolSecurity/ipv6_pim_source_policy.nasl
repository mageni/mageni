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
  script_oid("1.3.6.1.4.1.25623.1.0.150288");
  script_version("2020-10-06T07:40:27+0000");
  script_tag(name:"last_modification", value:"2020-10-07 09:36:44 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-07-13 12:54:01 +0000 (Mon, 13 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Deploying an IPv6 PIM Source Policy");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("vrp_current_configuration_section_include_multicast_ipv6.nasl", "vrp_current_configuration_pim.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"The source-policy command is used to filter the received multicast
data packets based on the source or group address.");

  exit(0);
}

# Check procedure:
# 1. display current-configuration | section include multicast ipv6 routing-enable: check for vpn-interfaces with 'multicast ipv6 routing-enable' command. If no vpn-instance with 'multicast routing-enable' exist, check fails.
# 2. display current-configuration configuration pim: Check for ipv6 vpn-instances without 'source-policy'. If no pim view exists, check fails.

include("policy_functions.inc");

major_version = get_kb_item("huawei/vrp/ssh-login/major_version");
multicast_routing_enable_error = get_kb_item("Policy/vrp/current_configuration/section/include/multicast_ipv6_routing_enable/error");
public_instance = get_kb_item("Policy/vrp/current_configuration/section/include/multicast_ipv6_routing_enable/public");
vpn_instances = get_kb_list("Policy/vrp/current_configuration/section/include/multicast_ipv6_routing_enable/vpn/*");

cmd = "display current-configuration | include multicast; display current-configuration configuration pim";
title = "Deploying an IPv6 PIM Source Policy";
solution = "Deploy IPv6 PIM source-policy.";
test_type = "SSH_Cmd";
default = "Enable";

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
}else{
  # check if 'display current-configuration | section include mutlicast ipv6 routing-enable' has errors
  if(multicast_routing_enable_error == "error"){
    value = "Error";
    compliant = "incomplete";
    comment = "Can not get sections with multicast ipv6 routing-enable command";
  }else if(multicast_routing_enable_error == "unknown command"){
    value = "Error";
    compliant = "incomplete";
    comment = "Device does not support command: display current-configuration | section include multicast ipv6 routing-enable";
  }else if(!public_instance && !vpn_instances){
    value = "No multicast ipv6 routing-enable in current configuration";
    compliant = "yes";
    comment = "Device has no multicast ipv6 routing-enable in display current-configuration";
  }else{
    # Check, if pim view exists and is not empty
    if(get_kb_item("Policy/vrp/current_configuration/pim/ERROR") || !get_kb_list("Policy/vrp/current_configuration/pim/*")){
      value = "PIM view does not exist";
      compliant = "no";
      comment = "Can not get PIM view.";
    }else{
      # Check for public instance if multicast routing enable is set
      if(public_instance){
        pim_view = get_kb_item("Policy/vrp/current_configuration/pim/pim-ipv6");
        if(!pim_view){
          public = "not compliant";
        }else if(pim_view !~ "source-policy"){
          public = "not compliant";
        }
      }
      # Check for each interface with 'multicast routing-enable' setting, if pim view of vpn instance has 'source-policy'
      # included.
      if(vpn_instances){
        foreach vpn_instance (keys(vpn_instances)){
          # get name of vpn interface and pim view of vpn interface
          vpn_instance = str_replace(string:vpn_instance, find:"Policy/vrp/current_configuration/section/include/multicast_ipv6_routing_enable/vpn/", replace:"");
          pim_view_vpn = get_kb_item("Policy/vrp/current_configuration/pim/pim-ipv6 vpn-instance " + vpn_instance);
          if(!pim_view_vpn){
            vpn = "not compliant";
            failed_vpn_instances += " " + vpn_instance;
          }else if(pim_view_vpn !~ "source-policy"){
            vpn = "not compliant";
            failed_vpn_instances += " " + vpn_instance;
          }
        }
      }

      # if public instance has multicast routing-enable but no source-policy in pim view, test fails
      if(public_instance && public == "not compliant"){
        value = "Disable";
        compliant = "no";
        comment = "Public interface has no source-policy set.";
      }

      # if any vpn instance has multicast routing-enable but no source-policy in pim view, test fails
      if(vpn_instances && vpn == "not compliant"){
        compliant = "no";
        value = "Disable";
        comment += "Following VPN instances have no source-policy set: " + failed_vpn_instances;
      }
    }

    if(!compliant){
      compliant = "Yes";
      value = "Enable";
      comment = "All vpn and public instances have source-policy enabled in PIM view.";
    }
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);