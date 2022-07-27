# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150520");
  script_version("2021-01-07T15:27:20+0000");
  script_tag(name:"last_modification", value:"2021-01-12 11:05:42 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-07 15:15:41 +0000 (Thu, 07 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Files in /etc/rc*.d directories (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/7/runlevel");

  script_tag(name:"summary", value:"Runlevels are a concept from UNIX System V used by the init
daemon or other system initialisation system to define modes of system operation.

Eight runlevels are permitted, the first seven are numbered 0-6 and the eighth is named S or s
(both are permitted).

Services and other system components are said to exist in one or more runlevels. When switching from
one runlevel to another, the services that should not exist in the new runlevel are stopped and the
services that only exist in the new runlevel are started.

This is performed by the /etc/init.d/rc script executed on a change of runlevel (by jobs run on the
runlevel event in the Upstart system). This script examines symlinks in the /etc/rc?.d directories,
symlinks beginning K are services to be stopped and symlinks beginning S are services to be started.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux//etc/rc.*d/ssh/ERROR", value:TRUE);
  exit(0);
}

cmd = "ls /etc/rc*.d 2>/dev/null";
ret = ssh_cmd(socket:sock, cmd:cmd, return_errors:FALSE);
if(!ret){
  set_kb_item(name:"Policy/linux//etc/rc.*d/ERROR", value:TRUE);
  exit(0);
}

set_kb_item(name:"Policy/linux//etc/rc.*d", value:ret);

exit(0);