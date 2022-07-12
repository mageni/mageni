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
  script_oid("1.3.6.1.4.1.25623.1.0.115009");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-07 13:57:57 +0000 (Tue, 07 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Check for users with DROP USER permission");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("zsql_db_user_sys_priv_query.nasl", "zsql_role_sys_privs.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"Searches for users and roles with DROP USER permission and
checks whether they are authorized to have it. A user with the DROP User permission can delete other
users. If this permission is no longer necessary, revoke it.");
  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT USERNAME, PRIVILEGE FROM DB_USER_SYS_PRIVS WHERE USERNAME = 'user_name' AND PRIVILEGE = 'DROP USER'";
title = "Check for users with DROP USER permission";
solution = "1) REVOKE DROP USER FROM user_name;
2) REVOKE DROP USER FROM role_name;";
test_type = "SQL_Query";
default = "User:Sys, Roles:DBA";

user_list = make_list();
role_list = make_list();

if(get_kb_item("Policy/zsql/zsql_db_user_sys_privs/ssh/ERROR") || get_kb_item("Policy/zsql/zsql_role_sys_privs/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/zsql_db_user_sys_privs/ERROR") || get_kb_item("Policy/zsql/zsql_role_sys_privs/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Cannot read table DB_USER_SYS_PRIVS or ROLE_SYS_PRIVS";
}else if((!grantee_list = get_kb_list("Policy/zsql/zsql_db_user_sys_privs/*")) ||
  (!role_sys_privs_list = get_kb_list("Policy/zsql/zsql_role_sys_privs/*"))){
  compliant = "incomplete";
  value = "error";
  comment = "Cannot parse table DB_USER_SYS_PRIVS or DB_USER_SYS_PRIVS";
}else{
  foreach key1(keys(grantee_list)){
    if( key1 =~ "DROP USER"){
      user = eregmatch(string:key1, pattern:"Policy/zsql/zsql_db_user_sys_privs/([^/]+)/*");
      if(user)
        user_list = make_list(user_list, user[1]);
    }
  }

  foreach key2(keys(role_sys_privs_list)){
    if(key2 =~ "DROP USER"){
      role = eregmatch(string:key2, pattern:"Policy/zsql/zsql_role_sys_privs/([^/]+)/*");
      if(role)
        role_list = make_list(role_list, role[1]);
    }
  }

  value = "User:" + policy_build_string_from_list(list:user_list, sep:",");
  value += ", Roles:" + policy_build_string_from_list(list:role_list, sep:",");

  compliant = policy_settings_lists_match(value:toupper(value), set_points:toupper(default), sep:",");
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
