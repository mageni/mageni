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
  script_oid("1.3.6.1.4.1.25623.1.0.150089");
  script_version("2020-06-17T13:37:18+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-01-20 10:25:12 +0100 (Mon, 20 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Read /etc/hosts.deny (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/5/hosts_access");

  script_tag(name:"summary", value:"The access control software consults two files. The search stops
at the first match:

  - Access will be granted when a (daemon,client) pair matches an entry in the /etc/hosts.allow file.

  - Otherwise, access will be denied when a (daemon,client) pair matches an entry in the /etc/hosts.deny file.

  - Otherwise, access will be granted.

A non-existing access control file is treated as if it were an empty file. Thus, access control can
be turned off by providing no access control files.

Note: This script stores information for other Policy Controls only.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success")){
  set_kb_item(name:"Policy/linux/etc/hosts_deny/ERROR", value:TRUE);
  set_kb_item(name:"Policy/linux/etc/hosts_deny/stat/ERROR", value:TRUE);
  exit(0);
}

sock = ssh_login_or_reuse_connection();
if(!sock){
  set_kb_item(name:"Policy/linux/etc/hosts_deny/ERROR", value:TRUE);
  set_kb_item(name:"Policy/linux/etc/hosts_deny/stat/ERROR", value:TRUE);
  exit(0);
}

stat_cmd = "stat /etc/hosts.deny";
stat_ret = ssh_cmd_without_errors(socket:sock, cmd:stat_cmd);
if(!stat_ret){
  set_kb_item(name:"Policy/linux/etc/hosts_deny/stat/ERROR", value:TRUE);
  exit(0);
}
set_kb_item(name:"Policy/linux/etc/hosts_deny/stat", value:stat_ret);

cat_cmd = "cat /etc/hosts.deny";
cat_ret = ssh_cmd_without_errors(socket:sock, cmd:cat_cmd);
if(!cat_ret){
  set_kb_item(name:"Policy/linux/etc/hosts_deny/ERROR", value:TRUE);
  exit(0);
}
set_kb_item(name:"Policy/linux/etc/hosts_deny", value:cat_ret);

exit(0);
