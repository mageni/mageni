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
  script_oid("1.3.6.1.4.1.25623.1.0.150165");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-03-16 11:10:17 +0000 (Mon, 16 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Only designated log hosts accepts remote rsyslog messages");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_rsyslog_conf.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/5/rsyslog.conf");

  script_tag(name:"summary", value:"Input plugin for plain TCP syslog. Replaces the deprecated -t
option. Can be used like this:

  - $ModLoad imtcp

  - $InputTCPServerRun 514");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep '$ModLoad' /etc/rsyslog.conf, grep '$InputTCPServerRun' /etc/rsyslog.conf";
title = "'$ModLoad imtcp' and '$InputTCPServerRun 514' in /etc/rsyslog.conf";
solution = "Add '$ModLoad imtcp' and '$InputTCPServerRun 514' to /etc/rsyslog.conf";
test_type = "SSH_Cmd";
default = "ModLoad imtcp, InputTCPServerRun 514";

if(get_kb_item("Policy/linux//etc/rsyslog.conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/rsyslog.conf/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/rsyslog.conf";
}else{
  content = get_kb_item("Policy/linux//etc/rsyslog.conf/content");
  value = egrep(string:content, pattern:"\$(ModLoad\s+imtcp|InputTCPServerRun\s+514)");
  foreach line (split(value)){
    if(line =~ "^\s*#")
      continue;

    if(line =~ "imtcp")
      imtcp = TRUE;

    if(line =~ "InputTCPServerRun")
      InputTCPServerRun = TRUE;
  }

  if(imtcp && InputTCPServerRun)
    compliant = "yes";
  else
    compliant = "no";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
