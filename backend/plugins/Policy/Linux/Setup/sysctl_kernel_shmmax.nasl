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
  script_oid("1.3.6.1.4.1.25623.1.0.150319");
  script_version("2020-11-09T15:35:56+0000");
  script_tag(name:"last_modification", value:"2020-11-11 11:10:35 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-09 15:16:41 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: sysctl kernel.shmmax");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_and_parse_sysctl.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/sysctl");
  script_xref(name:"URL", value:"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/tuning_and_optimizing_red_hat_enterprise_linux_for_oracle_9i_and_10g_databases/chap-oracle_9i_and_10g_tuning_guide-setting_shared_memory");

  script_tag(name:"summary", value:"This parameter defines the maximum size in bytes of a single
shared memory segment that a Linux process can allocate in its virtual address space.");

  exit(0);
}

include( "policy_functions.inc" );

cmd = "sysctl kernel.shmmax";
title = "sysctl kernel.shmmax";
solution = "sysctl -w kernel.shmmax = VALUE";
test_type = "Manual Check";
default = "None";

if( get_kb_item( "Policy/linux/sysctl/ssh/ERROR" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if( get_kb_item("Policy/linux/sysctl/ERROR" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run sysctl command";
}else{
  if( ! value = get_kb_item( "Policy/linux/sysctl/kernel.shmmax" ) ) {
    value = "Error";
    compliant = "incomplete";
    comment = "Could not find setting with sysctl.";
  }else{
    compliant = "incomplete";
    comment = "Please test the compliance status manually";
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );