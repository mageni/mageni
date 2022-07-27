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
  script_oid("1.3.6.1.4.1.25623.1.0.150543");
  script_version("2021-01-12T09:08:17+0000");
  script_tag(name:"last_modification", value:"2021-01-18 11:03:31 +0000 (Mon, 18 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-12 09:07:19 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Get iptables and ip6tables (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/iptables");
  script_xref(name:"URL", value:"https://linux.die.net/man/8/ip6tables");

  script_tag(name:"summary", value:"Iptables is used to set up, maintain, and inspect the tables of
IP packet filter rules in the Linux kernel. Several different tables may be defined. Each table
contains a number of built-in chains and may also contain user-defined chains.

Ip6tables is used to set up, maintain, and inspect the tables of IPv6 packet filter rules in the
Linux kernel. Several different tables may be defined. Each table contains a number of built-in
chains and may also contain user-defined chains.

Each chain is a list of rules which can match a set of packets. Each rule specifies what to do with
a packet that matches. This is called a 'target', which may be a jump to a user-defined chain in the
same table.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux/iptables/ssh/ERROR", value:TRUE);
  exit(0);
}

commands = make_list("iptables -L",
  "iptables -L INPUT -v -n",
  "iptables -L OUTPUT -v -n",
  "iptables -L -v -n",
  "ss -4tuln",
  "ip6tables -L",
  "ip6tables -L INPUT -v -n",
  "ip6tables -L OUTPUT -v -n",
  "ip6tables -L -v -n",
  "ss -6tuln"
);

foreach cmd (commands){
  ret = ssh_cmd(socket:sock, cmd:cmd, return_errors:FALSE);
  if(!ret){
    set_kb_item(name:"Policy/linux/iptables/" + cmd + "/ERROR", value:TRUE);
  }else{
    set_kb_item(name:"Policy/linux/iptables/" + cmd, value:ret);
  }
}

exit(0);