# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.115001");

  script_version("2020-06-16T13:29:02+0000");

  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-03-24 12:46:56 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Content of ADM_TAB_PRIVS database");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"This script writes the complete database of ADM_TAB_PRIVS to KB.

  Note:This script stores values in KB only and has no output.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/zsql/zsql/adm_tab_privs/ssh/ERROR", value:TRUE);
  exit(0);
}

query = 'dump table ADM_TAB_PRIVS into file \'STDOUT\' COLUMNS TERMINATED BY \'|\';';
db_adm_tab_privs = zsql_command(socket:sock, query:query);

if(!db_adm_tab_privs){
  set_kb_item(name:"Policy/zsql/zsql_adm_tab_privs/ERROR", value:TRUE);
}
foreach line(split(db_adm_tab_privs, keep:FALSE)){
  if(line =~ "SQL>"){
    line = str_replace(string:line, find:"SQL> ", replace:"");
  }
  items = eregmatch(string:line, pattern:"(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)");
  if(items){
    set_kb_item(name:"Policy/zsql/zsql_adm_tab_privs/"+items[1]+"/"+items[3]+"/"+items[5]+"/OWNER", value:items[2]);
    set_kb_item(name:"Policy/zsql/zsql_adm_tab_privs/"+items[1]+"/"+items[3]+"/"+items[5]+"/OBJECT_TYPE", value:items[4]);
    set_kb_item(name:"Policy/zsql/zsql_adm_tab_privs/"+items[1]+"/"+items[3]+"/"+items[5]+"/GRANTABLE", value:items[6]);
  }else{
    set_kb_item(name:"Policy/zsql/zsql_adm_tab_privs/empty", value:TRUE);
  }
}
exit(0);
