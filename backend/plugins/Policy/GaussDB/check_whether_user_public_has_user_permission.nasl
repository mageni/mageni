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
  script_oid("1.3.6.1.4.1.25623.1.0.115012");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-14 13:57:57 +0000 (Tue, 14 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Check whether User PUBLIC has Object Permission");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("zsql_adm_tab_privs_query.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"Every user automatically belongs to user PUBLIC. For database
security, do not grant object permissions to user PUBLIC");
  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT * FROM ADM_TAB_PRIVS WHERE GRANTEE='PUBLIC'";
title = "Check whether user PUBLIC has object permissions";
solution = "REVOKE ALL ON object_name FROM public";
test_type = "Manual Check";
default = "None";

if(get_kb_item("Policy/zsql/zsql_adm_tab_privs/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host for ADM TAB PRIVS";
}else if(get_kb_item("Policy/zsql/zsql_adm_tab_privs/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Cannot read table ADM_TAB_PRIVS";
}else{
  compliant = "incomplete";
  comment = "No automatic test possible. Please run 'SELECT * FROM ADM_TAB_PRIVS WHERE GRANTEE='PUBLIC';' ";
  comment += "and check for object permissions to public users.";
  value = "None";
  # select_view_object_names = make_list("DB_ARGUMENTS", "DB_COL_COMMENTS", "DB_CONSTRAINTS", "DB_DBLINK_TABLES",
  # "DB_DBLINK_TAB_COLUMNS", "DB_DEPENDENCIES", "DB_VIEW_DEPENDENCIES", "DB_DISTRIBUTE_RULES", "DB_DIST_RULE_COLS",
  # "DB_HISTOGRAMS", "DB_INDEXES", "DB_IND_COLUMNS", "DB_IND_PARTITIONS", "DB_OBJECTS", "DB_PART_COL_STATISTICS",
  # "DB_PART_KEY_COLUMNS", "DB_PART_STORE", "DB_PART_TABLES", "DB_PROCEDURES", "DB_SEQUENCES", "DB_SOURCE",
  # "DB_SYNONYMS", "DB_TABLES", "DB_TAB_COLS", "DB_TAB_COLUMNS", "DB_TAB_COL_STATISTICS", "DB_TAB_COMMENTS",
  # "DB_TAB_DISTRIBUTE", "DB_TAB_PARTITIONS", "DB_TAB_STATISTICS", "DB_TRIGGERS", "DB_VIEWS", "DB_VIEW_COLUMNS",
  # "NLS_SESSION_PARAMETERS", "ROLE_SYS_PRIVS", "MY_ARGUMENTS", "MY_COL_COMMENTS", "MY_CONSTRAINTS", "MY_CONS_COLUMNS",
  # "MY_DEPENDENCIES", "MY_FREE_SPACE", "MY_HISTOGRAMS", "MY_INDEXES", "MY_IND_COLUMNS", "MY_IND_PARTITIONS",
  # "MY_IND_STATISTICS", "MY_JOBS", "MY_OBJECTS", "MY_PART_COL_STATISTICS", "MY_PART_KEY_COLUMNS", "MY_PART_STORE",
  # "MY_PART_TABLES", "MY_PROCEDURES", "MY_ROLE_PRIVS", "MY_SEGMENTS", "MY_SEQUENCES", "MY_SOURCE", "MY_SQL_MAPS",
  # "MY_SYNONYMS", "MY_SYS_PRIVS", "MY_TABLES", "MY_TAB_COLS", "MY_TAB_COLUMNS", "MY_TAB_COL_STATISTICS",
  # "MY_TAB_COMMENTS", "MY_TAB_DISTRIBUTE", "MY_TAB_MODIFICATIONS", "MY_TAB_PARTITIONS", "MY_TAB_PRIVS",
  # "MY_TAB_STATISTICS", "MY_TRIGGERS", "MY_USERS", "MY_VIEWS", "MY_VIEW_COLUMNS", "DV_ME", "DV_USER_PARAMETERS",
  # "DB_VIEW_DEPENDENCIES");

  # procedure_execute_object_names = make_list("DBMS_LOB", "DBMS_OUTPUT", "DBMS_RAFT", "DBMS_RANDOM",
  # "DBMS_SQL", "DBMS_STANDARD", "DBMS_STATS", "DBMS_UTILITY");

  # table_select_object_names = make_list("SYS_DUMMY");

  # foreach item(select_view_object_names){
  #   owner = "";
  #   object_type = "";
  #   grantable = "";

  #   owner = get_kb_item("Policy/zsql/zsql_adm_tab_privs/PUBLIC/"+ item +"/SELECT/OWNER");
  #   object_type = get_kb_item("Policy/zsql/zsql_adm_tab_privs/PUBLIC"+ item + "/SELECT/OBJECT_TYPE");
  #   grantable = get_kb_item("Policy/zsql/zsql_adm_tab_privs/PUBLIC/"+ item +  "/SELECT/GRANTABLE");

  #   if(owner != "SYS" || object_type != "VIEW" || grantable != "NO"){
  #     value += ", " + item;
  #   }
  # }

  # foreach item(procedure_execute_object_names){
  #   owner = "";
  #   object_type = "";
  #   grantable = "";

  #   owner = get_kb_item("Policy/zsql/zsql_adm_tab_privs/PUBLIC/"+ item +"/EXECUTE/OWNER");
  #   object_type = get_kb_item("Policy/zsql/zsql_adm_tab_privs/PUBLIC"+ item + "/EXECUTE/OBJECT_TYPE");
  #   grantable = get_kb_item("Policy/zsql/zsql_adm_tab_privs/PUBLIC/"+ item +  "/EXECUTE/GRANTABLE");

  #   if(owner != "SYS" || object_type != "PROCEDURE" || grantable != "NO"){
  #     value += ", " + item;
  #   }
  # }

  # foreach item(procedure_execute_object_names){
  #   owner = "";
  #   object_type = "";
  #   grantable = "";

  #   owner = get_kb_item("Policy/zsql/zsql_adm_tab_privs/PUBLIC/"+ item +"/SELECT/OWNER");
  #   object_type = get_kb_item("Policy/zsql/zsql_adm_tab_privs/PUBLIC"+ item + "/SELECT/OBJECT_TYPE");
  #   grantable = get_kb_item("Policy/zsql/zsql_adm_tab_privs/PUBLIC/"+ item +  "/SELECT/GRANTABLE");

  #   if(owner != "SYS" || object_type != "TABLE" || grantable != "NO"){
  #     value += ", " + item;
  #   }
  # }

  # if(value){
  #   compliant = "no";
  #   value = str_replace(string:value, find:", ", replace:"", count:1);
  # }else{
  #   compliant = "yes";
  #   value = "None";
  # }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
