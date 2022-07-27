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
  script_oid("1.3.6.1.4.1.25623.1.0.150121");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-02-03 13:14:22 +0100 (Mon, 03 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: System Information in /etc/issue");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_issue.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"No;Yes", id:1);

  script_xref(name:"URL", value:"https://www.putorius.net/custom-issue-login-screen-linux.html");

  script_tag(name:"summary", value:"The content of /etc/issue file is displayed to users after
successful local login.

Following escape chars display information about the system:

  - \m: machine architecture

  - \r: operating system release

  - \s: operating system name

  - \v: operating system version");

  exit(0);
}

include("policy_functions.inc");

cmd = "cat /etc/issue";
title = "System Information in /etc/issue";
solution = "Modify content of /etc/issue";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux//etc/issue/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/issue";
}else{
  stat = get_kb_item("Policy/linux//etc/issue/content");
  if(ereg(string:stat, pattern:'(\\\\[r,v,m,s])', multiline:TRUE))
    value = "Yes";
  else
    value = "No";

  compliant = policy_setting_exact_match(value:value, set_point:default);
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
