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
  script_oid("1.3.6.1.4.1.25623.1.0.150220");
  script_version("2020-07-29T07:27:10+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-16 11:08:58 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Server Logging Levels");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"7", id:1);

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"The _LOG_LEVEL parameter specifies the levels of run logs and
debug logs to be written into the server. The default value is 7, indicating that run logs in all
levels are written into the server.

If _LOG_LEVEL is set to 0, not only RUN and DEBUG logging, but also ALARM logging will be disabled.
This helps handle emergencies.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");

cmd = "SELECT (SELECT VALUE FROM DV_PARAMETERS WHERE NAME = '_LOG_LEVEL') & (1 | 2 | 4) AS RUN_LOG;";
title = "Server Logging Levels";
solution = "Change the value of _LOG_LEVEL in ${GSDB_DATA}/cfg/zengine.ini, or run
'ALTER SYSTEM SET _LOG_LEVEL = 7;'";
test_type = "SQL_Query";
default = script_get_preference("Value", id:1);

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(!query_return = zsql_command(socket:sock, query:cmd)){
  compliant = "incomplete";
  value = "error";
  comment = "No result for query";
}else{
  match = eregmatch(string:query_return, pattern:"([0-9]+)");
  if(!match){
    compliant = "incomplete";
    value = "error";
    comment = "Can not parse output of command";
  }else{
    value = match[1];
    compliant = policy_setting_min_match(value:value, set_point:default);
  }
}

policy_reporting(result:value, default:">= " + default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
