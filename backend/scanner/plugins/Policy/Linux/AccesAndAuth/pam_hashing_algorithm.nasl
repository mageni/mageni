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
  script_oid("1.3.6.1.4.1.25623.1.0.150134");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-02-13 09:39:22 +0000 (Thu, 13 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Password hashing algorithm");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_pamd.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"sha512", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/8/pam_unix");

  script_tag(name:"summary", value:"The hashing algorithm can be set in following module:

  - pam_unix: Module for traditional password authentication

Use the sha512 option to enforce encryption with the SHA512 algorithm. If the SHA512 algorithm is
not known to the crypt function, fall back to MD5.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep -E '^\s*password\s+sufficient\s+pam_unix.so\' /etc/pam.d/password-password /etc/pam.d/system-auth";
title = "Password hashing algorithm";
solution = "Set encryption type option for pam_unix module in /etc/pam.d/common-password, /etc/pam.d/password-auth or /etc/pam.d/system-auth";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);
value = "";

if(get_kb_item("Policy/linux/etc/pam.d/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host possible.";
}else{
  files = make_list("/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth");
  foreach file (files){
    if(get_kb_item("Policy/linux/" + file + "/content/ERROR"))
      continue;

    content = get_kb_item("Policy/linux/" + file + "/content");
    pattern = "^\s*password\s+sufficient\s+pam_unix.so\s+.*" + default + "\s*.*$";
    match = egrep(string:content, pattern:pattern);
    if(match){
      value = chomp(match);
    }
  }

  if(value == ""){
    compliant = "no";
    value = "None";
  }else{
    compliant = "yes";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
