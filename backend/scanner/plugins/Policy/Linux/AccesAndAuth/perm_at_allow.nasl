# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150103");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-01-24 09:25:45 +0100 (Fri, 24 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Permissions on /etc/at.allow");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "stat_cron_files.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Permissions", type:"entry", value:"700", id:1);
  script_add_preference(name:"Owner", type:"entry", value:"root:root", id:2);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/at.allow");
  script_xref(name:"URL", value:"https://linux.die.net/man/2/stat");
  script_xref(name:"URL", value:"https://linux.die.net/man/1/at");

  script_tag(name:"summary", value:"The at.allow file controls who can submit jobs via at or batch.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "stat /etc/at.allow";
title = "Permissions on /etc/at.allow";
solution = "chmod PERMISSIONS /etc/at.allow; chown USER:GROUP /etc/at.allow";
test_type = "SSH_Cmd";
default_permissions = script_get_preference("Permissions", id:1);
default_owner = script_get_preference("Owner", id:2);
default = "Permissions:" + default_permissions + ", Owner:" + default_owner;

if(get_kb_item("Policy/linux/cron/ERROR") || get_kb_item("Policy/linux/cron//etc/at.allow/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not get information about /etc/at.allow file.";
}else{
  permissions = get_kb_item("Policy/linux/cron//etc/at.allow/perm");
  owner = get_kb_item("Policy/linux/cron//etc/at.allow/user_group");
  if(policy_access_permissions_match_or_stricter(value:permissions, set_point:default_permissions) == "yes" &&
    policy_setting_exact_match(value:owner, set_point:default_owner) == "yes"){
    compliant = "yes";
  }else{
    compliant = "no";
  }
  value = "Permissions:" + permissions + ", Owner:" + owner;
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
