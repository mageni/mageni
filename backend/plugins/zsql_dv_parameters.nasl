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
  script_oid("1.3.6.1.4.1.25623.1.0.150195");
  script_version("2020-07-02T11:53:44+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-06 13:36:40 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Content of DV_PARAMETERS Database");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"This script writes the complete database of DV_PARAMETERS to KB.

Note: this script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");
include("host_details.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/zsql/dv_parameters/ssh/ERROR", value:TRUE);
  exit(0);
}

query = 'dump table DV_PARAMETERS into file \'STDOUT\' COLUMNS TERMINATED BY \'|\';';
dv_parameters = zsql_command(socket:sock, query:query);

if(!dv_parameters){
  set_kb_item(name:"Policy/zsql/dv_parameters/ERROR", value:TRUE);
}else{
  foreach line(split(dv_parameters, keep:FALSE)){
    if(line=~"SQL> "){
      line = str_replace(string:line, find:"SQL> ", replace:"");
    }

    items = split(line, sep:"|", keep:FALSE);
    if(max_index(items) == 10){
      # GaussDB T1.0.2
      # NAME,VALUE,RUNTIME_VALUE,DEFAULT_VALUE,ISDEFAULT,MODIFIABLE,DESCRIPTION,RANGE,DATATYPE,EFFECTIVE
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/value", value:items[1]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/runtime_value", value:items[2]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/default_value", value:items[3]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/isdefault", value:items[4]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/modifiable", value:items[5]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/description", value:items[6]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/range", value:items[7]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/datatype", value:items[8]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/effective", value:items[9]);
    }else if(max_index(items) == 9){
      # GaussDB 100,200
      # NAME,VALUE,DEFAULT_VALUE,ISDEFAULT,MODIFIABLE,DESCRIPTION,RANGE,DATATYPE,EFFECTIVE
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/value", value:items[1]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/default_value", value:items[2]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/isdefault", value:items[3]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/modifiable", value:items[4]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/description", value:items[5]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/range", value:items[6]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/datatype", value:items[7]);
      set_kb_item(name:"Policy/zsql/dv_parameters/" + items[0] + "/effective", value:items[8]);
    }else{
      set_kb_item(name:"Policy/zsql/dv_parameters/empty", value:TRUE);
    }
  }
}

exit(0);
