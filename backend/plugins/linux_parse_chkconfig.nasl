# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.150309");
  script_version("2020-11-05T15:49:51+0000");
  script_tag(name:"last_modification", value:"2020-11-11 11:10:35 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-04 14:41:54 +0000 (Wed, 04 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: read and parse chkconfig --list");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/chkconfig");

  script_tag(name:"summary", value:"chkconfig provides a simple command-line tool for maintaining
the /etc/rc[0-6].d directory hierarchy by relieving system administrators of the task of directly
manipulating the numerous symbolic links in those directories.

This implementation of chkconfig was inspired by the chkconfig command present in the IRIX operating
system. Rather than maintaining configuration information outside of the /etc/rc[0-6].d hierarchy,
however, this version directly manages the symlinks in /etc/rc[0-6].d. This leaves all of the
configuration information regarding what services init starts in a single location.");
  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  set_kb_item( name:"policy/linux/chkconfig/ssh/ERROR", value:TRUE );
  exit( 0 );
}

cmd = "chkconfig --list";
ret = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );
if( !ret ) {
  set_kb_item( name:"policy/linux/chkconfig/ERROR", value:TRUE );
  exit( 0 );
}

foreach line ( split( ret, keep:FALSE ) ) {
  values = eregmatch( string:line, pattern:"^\s*(.+)\s+0:(on|off)\s+1:(on|off)\s+2:(on|off)\s+3:(on|off)\s+4:(on|off)\s+5:(on|off)\s+6:(on|off)\s*$" );

  if( values ) {
    name = chomp(values[1]);
    level0 = values[2];
    level1 = values[3];
    level2 = values[4];
    level3 = values[5];
    level4 = values[6];
    level5 = values[7];
    level6 = values[8];

    set_kb_item( name:"policy/linux/chkconfig/" + name + "/level0", value:level0 );
    set_kb_item( name:"policy/linux/chkconfig/" + name + "/level1", value:level1 );
    set_kb_item( name:"policy/linux/chkconfig/" + name + "/level2", value:level2 );
    set_kb_item( name:"policy/linux/chkconfig/" + name + "/level3", value:level3 );
    set_kb_item( name:"policy/linux/chkconfig/" + name + "/level4", value:level4 );
    set_kb_item( name:"policy/linux/chkconfig/" + name + "/level5", value:level5 );
    set_kb_item( name:"policy/linux/chkconfig/" + name + "/level6", value:level6 );
  }
}

exit( 0 );