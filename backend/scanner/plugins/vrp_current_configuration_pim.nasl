# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150260");
  script_version("2020-10-06T07:31:27+0000");
  script_tag(name:"last_modification", value:"2020-10-07 09:36:44 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-05-15 12:56:59 +0000 (Fri, 15 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Read current-configuration pim");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_vrp_network_device_ssh_login_detect.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"Get the current PIM configuration of the VRP device.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");

if(!get_kb_item("huawei/vrp/detected")){
  set_kb_item(name:"Policy/vrp/installed/ERROR", value:TRUE);
  exit(0);
}

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/vrp/ssh/ERROR", value:TRUE);
  exit(0);
}

cmd = "display current-configuration configuration pim";
ret = ssh_cmd(socket:sock, cmd:cmd, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
              retry:10, force_reconnect:TRUE, clear_buffer:TRUE);

if(!ret){
  set_kb_item(name:"Policy/vrp/current_configuration/pim/ERROR", value:TRUE);
  exit(0);
}

foreach view (split(ret, sep:"#", keep:FALSE)){
  if(view =~ "^\s*(return)\s*$")
    continue;
  view = ereg_replace(string:view, pattern:"^\s+", replace:"");
  if(!view)
    continue;
  key = eregmatch(string:view, pattern:'^[^\n]+');
  # pim-ipv6 and pim ipv6 are the same
  if(key[0] == "pim ipv6")
    key[0] = "pim-ipv6";

  set_kb_item(name:"Policy/vrp/current_configuration/pim/" + key[0], value:view);
}

exit(0);
