# Copyright (C) 2019 Greenbone Networks GmbH
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.109809");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-03-13 08:35:57 +0100 (Wed, 13 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Restrict users for su command");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_pamd.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"User list (semi-colon separated)", type:"entry", value:"root", id:1);

  script_xref(name:"URL", value:"http://www.man7.org/linux/man-pages/man1/su.1.html");

  script_tag(name:"summary", value:"su allows to run commands with a substitute user and group ID.

When called with no user specified, su defaults to running an interactive shell as root. When user
is specified, additional arguments can be supplied, in which case they are passed to the shell.

With adding 'auth required pam_wheel.so use_uid' to /etc/pam.d/su only members of the administrative
group wheel can use the su command.");
  exit(0);
}

include("policy_functions.inc");

cmd = "grep '^\s+auth\s+required\s+pam_wheel.so\s+use_uid' /etc/pam.d/su";
title = "Restrict the use of su";
solution = "Add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su";
test_type = "SSH_Cmd";
# script_preference was used in prior version, but is not needed anymore. But as we can not remove
# preferences, this has to stay in the description block.
default = "Yes";

if(get_kb_item("Policy/linux//etc/pam.d/su/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/pam.d/su";
}else{
  content = get_kb_item("Policy/linux//etc/pam.d/su/content");
  match = egrep(string:content, pattern:"^\s*auth\s*required\s*pam_wheel.so\s*use_uid");
  if(match)
    value = "Yes";
  else
    value = "No";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);