# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150276");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-19 09:53:39 +0000 (Fri, 19 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: PASS_MIN_DAYS in /etc/login.defs");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_login_defs.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"7", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/login.defs");

  script_tag(name:"summary", value:"The '/etc/login.defs' file defines the site-specific
configuration for the shadow password suite. Any changes to this file will apply for the 'usermod'
command and only for new users.

  - PASS_MIN_DAYS: The minimum number of days allowed between password changes. Any password changes
attempted sooner than this will be rejected. If not specified, -1 will be assumed (which disables
the restriction).

Note: Multiple set_points can be set with comma-separated entry.");

  exit(0);
}

include("policy_functions.inc");

function get_value(content, option){
  grep = egrep(string:content, pattern:"^\s*" + option);
  if(!grep)
    return("-1");

  match = eregmatch(string:grep, pattern:option + "\s+([0-9]*)");
  if(match[1])
    return(chomp(match[1]));
  else
    return("-1");
}

cmd = "grep ^PASS_MIN_DAYS /etc/login.defs";
title = "PASS_MIN_DAYS in /etc/login.defs";
solution = "Set PASS_MIN_DAYS in /etc/login.defs";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux//etc/login.defs/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/login.defs";
}else{
  content = get_kb_item("Policy/linux//etc/login.defs/content");
  value = get_value(content:content, option:'^PASS_MIN_DAYS');

  if(value >< default)
    compliant = "yes";
  else
    compliant = "no";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);