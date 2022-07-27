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
  script_oid("1.3.6.1.4.1.25623.1.0.150194");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-06 13:12:37 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Disabling the Use of 0.0.0.0 and :: for Listening");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("zsql_dv_parameters.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"0.0.0.0 indicates that all available IPv4 addresses on the local
host are listened, and :: indicates that all available IPv6 addresses on the local host are listened.");

  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT NAME, VALUE FROM DV_PARAMETERS WHERE NAME = 'LSNR_ADDR' AND VALUE IN ('0.0.0.0', '::');";
title = "Disabling the Use of 0.0.0.0 and :: for Listening";
solution = "Change the value of LSNR_ADDR in the zengine.ini configuration file to a local IP address
and restart the database for the change to take effect. The path of the zengine.ini file is
{GSDB_DATA}/cfg/zengine.ini.";
test_type = "SQL_Query";
default = "Not '0.0.0.0' or '::'";

if(get_kb_item("Policy/zsql/dv_parameters/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/dv_parameters/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not read table DV_PARAMETERS";
}else if(!value = get_kb_item("Policy/zsql/dv_parameters/LSNR_ADDR/value")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not find value for LSNR_ADDR in table DV_PARAMETERS";
}else{
  if(value =~ "0.0.0.0" || value =~ "::")
    compliant = "no";
  else
    compliant = "yes";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
