# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109738");
  script_version("2020-07-29T07:27:10+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-01-16 08:27:43 +0100 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Blacklisted packages");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Blacklisted packages", type:"entry", value:"prelink,setroubleshoot,mcstrans,xorg-x11,xserver-xorg,ypbind,rsh,talk,telnet,openldap-clients", id:1);
  script_add_preference(name:"Show partial matches", type:"radio", value:"No;Yes", id:2);

  script_tag(name:"summary", value:"Some packages have security issues or should not be installed
  on the host for other reasons.

  This script checks if any of the given packages is installed on the host.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "[rpm -q, dpkg -s]  PACKAGE";
title = "Blacklisted Packages";
solution = "Remove packages";
test_type = "SSH_Cmd";
default = script_get_preference("Blacklisted packages", id:1);
partial_match = script_get_preference("Show partial matches", id:2);
if( partial_match == "Yes")
  partial_match = TRUE;
else
  partial_match = FALSE;

if(!get_kb_item("login/SSH/success")) {
  value = "Error";
  compliant = "incomplete";
  note = "No SSH connection possible";
} else {
  package_list = policy_build_list_from_string(str:default);

  foreach package (package_list) {
    version = get_package_version(package:package, partial_match:partial_match);
    if(version)
      value += "," + package;
  }

  if(value) {
    value = str_replace(string:value, find:",", replace:"", count:1);
    compliant = "no";
  } else {
    compliant = "yes";
    value = "None";
  }
  note = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:note);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
