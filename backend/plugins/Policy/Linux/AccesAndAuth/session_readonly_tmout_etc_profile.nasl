# Copyright (C) 2020 Greenbone Networks GmbH
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.150129");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-02-06 12:23:23 +0100 (Thu, 06 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: 'readonly TMOUT' in /etc/profile");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/Bash-Beginners-Guide/sect_03_01.html");

  script_tag(name:"summary", value:"When invoked interactively with the --login option or when
invoked as sh, Bash reads the /etc/profile instructions. These usually set the shell variables PATH,
USER, MAIL, HOSTNAME and HISTSIZE.

On some systems, the umask value is configured in /etc/profile, on other systems this file holds
pointers to other configuration files such as:

  - /etc/inputrc, the system-wide Readline initialization file where you can configure the command
line bell-style.

  - the /etc/profile.d directory, which contains files configuring system-wide behavior of specific
programs.

All settings that you want to apply to all your users' environments should be in this file.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "grep 'readonly TMOUT' /etc/profile";
title = "'readonly TMOUT' in /etc/profile";
solution = "Add 'readonly TMOUT' in /etc/profile";
test_type = "SSH_Cmd";
default = "yes";

if(get_kb_item("Policy/linux/shell_initialization/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to remote host";
}else if(get_kb_item("Policy/linux/shell_initialization/etc/profile/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/profile";
}else{
  content = get_kb_item("Policy/linux/shell_initialization/etc/profile");
  match = egrep(string:content, pattern:"^\s*readonly\s*TMOUT");
  if(match){
    value = "yes";
    compliant = "yes";
  }else{
    value = "no";
    compliant = "no";
  }
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
