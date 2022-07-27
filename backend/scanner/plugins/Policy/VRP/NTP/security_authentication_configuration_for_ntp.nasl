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
  script_oid("1.3.6.1.4.1.25623.1.0.150293");
  script_version("2020-10-06T07:40:27+0000");
  script_tag(name:"last_modification", value:"2020-10-07 09:36:44 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-07-13 14:22:23 +0000 (Mon, 13 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Security authentication configuration for NTP clients and level-2 or multi-level servers");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("vrp_current_configuration_ntp.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"Configure security verification for the NTP client and level-2
or multi-level servers.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

port = get_kb_item("huawei/vrp/ssh-login/port");
model = get_kb_item("huawei/vrp/ssh-login/" + port + "/model");
major_version = get_kb_item("huawei/vrp/ssh-login/major_version");

cmd = "display current-configuration | include ntp";
title = "Configuring NTP Client Security Authentication";
solution = "Configure security verification for the NTP client.";
test_type = "SSH_Cmd";
default = "Enabled";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(!model || !major_version){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine model or version of VRP device.";
}else if(model =~ "^CE" && major_version =~ "^8"){ # nb: Test doesn't apply to CE devices on VRP V8
  # Don't report anything if test not applicable
  exit(0);
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(!current_configuration = get_kb_item("Policy/vrp/current_configuration/ntp")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the current configuration for ntp.";
}else if(current_configuration !~ "ntp"){
  value = "Not applicable";
  compliant = "yes";
  comment = "This check is applicable if NTP is enabled only. Did not find 'ntp' included in current-configuration.";
}else if(current_configuration !~ "ntp-service\s+authentication-keyid" ||
         current_configuration !~ "ntp-service\s+authentication\s+enable" ||
         current_configuration !~ "ntp-service\s+reliable\s+authentication-keyid"){
  value = "Not applicable";
  compliant = "yes";
  comment = "This check is applicable if following settings are configured: ntp-service authentication-keyid,";
  comment += " ntp-service authentication enable and ntp-service reliable authentication-keyid.";
}else{
  if(current_configuration =~ "ntp-service\s+unicast-server\s+[a-z,A-Z,0-9,:,., ]+\s+authentication-keyid")
    value = "Enabled";
  else
    value = "Disabled";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
