# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.115013");
  script_version("2020-07-29T07:27:10+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-29 11:22:57 +0000 (Wed, 29 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Check for users and roles with DBA role");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");

  script_tag(name:"summary", value:"The DBA role has all system permissions. Therefore, use this
role only when absolutely necessary. You are advised to use a user not inheriting the DBA role to
connect to the database.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = 'SELECT GRANTEE FROM ADM_ROLE_PRIVS WHERE GRANTEE in (SELECT GRANTED_ROLE FROM ADM_ROLE_PRIVS WHERE GRANTEE in (SELECT USERNAME FROM DB_USERS) UNION SELECT USERNAME FROM DB_USERS) AND GRANTEE NOT IN (\'SYS\') AND GRANTED_ROLE = \'DBA\';';
title = "Check for users and roles with DBA role";
solution = "Run 'REVOKE DBA FROM user_name;' and 'REVOKE DBA FROM role_name;'";
test_type = "SQL_Query";
default = "None";

if ( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
} else if ( ! dba_role = zsql_command( socket:sock, query:cmd ) ) {
  compliant = "incomplete";
  value = "error";
  comment = "Can not query database.";
}else if( dba_role =~ "0 rows fetched" ) {
  compliant = "yes";
  value = "None";
}else{
  dba_role_replace = ereg_replace(string:dba_role, pattern:"\s+", replace:",");
  users = eregmatch(string:dba_role_replace, pattern:"----,(.+),[0-9]+,rows,fetched");
  value = users[1];
  compliant = "no";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);