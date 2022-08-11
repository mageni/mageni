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
  script_oid("1.3.6.1.4.1.25623.1.0.150101");
  script_version("2020-01-23T15:56:41+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 16:36:15 +0100 (Thu, 23 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Access permissions to cron files files (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/cron");
  script_xref(name:"URL", value:"https://linux.die.net/man/1/crontab");

  script_tag(name:"summary", value:"Cron runs specific commands at specific periods. Access to the
configuration files should be limited.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux/cron/ERROR", value:TRUE);
  exit(0);
}

cron_files = make_list("/etc/crontab",
"/etc/cron.hourly",
"/etc/cron.daily",
"/etc/cron.weekly",
"/etc/cron.monthly",
"/etc/cron.d",
"/etc/cron.deny",
"/etc/at.deny",
"/etc/cron.allow",
"/etc/at.allow");

foreach file (cron_files){
  cmd = "stat " + file + " 2>/dev/null";
  stat = ssh_cmd_without_errors(socket:sock, cmd:cmd);
  if(stat){
    user = policy_chown_get_uid(stat:stat);
    group = policy_chown_get_gid(stat:stat);
    perm = policy_get_access_permissions(stat:stat);
    set_kb_item(name:"Policy/linux/cron/" + file + "/user_group", value:user + ":" + group);
    set_kb_item(name:"Policy/linux/cron/" + file + "/perm", value:perm);
  }
  else{
    set_kb_item(name:"Policy/linux/cron/" + file + "/ERROR", value:TRUE);
  }
}

exit(0);