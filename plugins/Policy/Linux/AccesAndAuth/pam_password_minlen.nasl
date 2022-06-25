# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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
  script_oid("1.3.6.1.4.1.25623.1.0.150267");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-11 13:09:53 +0000 (Thu, 11 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: minlen in pam_pwquality.so");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_pamd.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"14", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/8/pam_pwquality");

  script_tag(name:"summary", value:"The pam_pwquality module can be plugged into the password stack
of a given service to provide some plug-in strength-checking for passwords. The code was originally
based on pam_cracklib module and the module is backwards compatible with its options.

  - minlen: The minimum acceptable size for the new password (plus one if credits are not disabled
which is the default). In addition to the number of characters in the new password, credit (of +1
in length) is given for each different kind of character (other, upper, lower and digit). The
default for this parameter is 9. Note that there is a pair of length limits also in Cracklib, which
is used for dictionary checking, a 'way too short' limit of 4 which is hard coded in and a build
time defined limit (6) that will be checked without reference to minlen.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep minlen /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password";
title = "Minimum acceptable size for the new password";
solution = "Set minlen=VALUE in /etc/pam.d/common-password, /etc/pam.d/password-auth or /etc/pam.d/system-auth";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/etc/pam.d/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host possible.";
}else{
  files = make_list("/etc/pam.d/system-auth", "/etc/pam.d/password-auth", "/etc/pam.d/common-password");
  foreach file (files){
    if(get_kb_item("Policy/linux/" + file + "/content/ERROR"))
      continue;

    content = get_kb_item("Policy/linux/" + file + "/content");
    password_required_pam_pwquality = egrep(string:content, pattern:"pam_pwquality.so");
    foreach line (split(password_required_pam_pwquality, keep:FALSE)){
      minclass_match = eregmatch(string:line, pattern:"minlen=([0-9]+)");
      if(minclass_match)
        value = minclass_match[1];
    }
  }

  if(!value){
    value = "None";
    compliant = "no";
    comment = "Could not find minlen option";
  }else{
    compliant = policy_setting_min_match(value:int(value), set_point:int(default));
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);