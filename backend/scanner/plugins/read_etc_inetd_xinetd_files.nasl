# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.150506");
  script_version("2021-01-04T14:44:13+0000");
  script_tag(name:"last_modification", value:"2021-01-11 11:04:52 +0000 (Mon, 11 Jan 2021)");
  script_tag(name:"creation_date", value:"2020-12-30 11:55:56 +0000 (Wed, 30 Dec 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Read /etc/inetd.* and /etc/xinetd.* files");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/xinetd");

  script_tag(name:"summary", value:"xinetd performs the same function as inetd: it starts programs
that provide Internet services. Instead of having such servers started at system initialization time,
and be dormant until a connection request arrives, xinetd is the only daemon process started and it
listens on all service ports for the services listed in its configuration file. When a request comes
in, xinetd starts the appropriate server. Because of the way it operates, xinetd (as well as inetd)
is also referred to as a super-server.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include( "ssh_func.inc" );
include( "policy_functions.inc" );

function parse_xinetd_conf ( filepath, socket ) {
  local_var filepath, socket, cmd, ret, services, service, service_name, pattern, settings;

  cmd = "cat " + filepath + " 2>/dev/null";
  ret = ssh_cmd( socket:socket, cmd:cmd );

  if( ! ret )
    return;

  services = egrep(string:ret, pattern:"^\s*service", multiline:TRUE);

  foreach service ( split( services, keep:FALSE ) ) {
    service_name = eregmatch( string:chomp( service ), pattern:"^\s*service\s+(.+)" );
    pattern = service + "\s+\{([^}]+)\}";
    settings = eregmatch( string:ret, pattern:pattern );

    if( service_name && settings ) {
      set_kb_item( name:"Policy/linux/etc/xinetd.conf/" + service_name[1], value:settings[1] );
    }
  }

  return;
}

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  set_kb_item( name:"Policy/linux/inetd/ssh/ERROR", value:TRUE );
  set_kb_item( name:"Policy/linux/xinetd/ssh/ERROR", value:TRUE );
  exit( 0 );
}

# /etc/inetd.*
inetd_files = "/etc/inetd.*";
filelist = ssh_find_file( file_name:inetd_files, sock:sock, useregex:TRUE );

if( ! filelist ) {
  set_kb_item( name:"Policy/linux/inetd/ERROR", value:TRUE );
} else {
  foreach file( filelist ) {
    policy_linux_file_content( socket:sock, file:chomp( file ) );
  }
}

# /etc/xinetd./
xinetd_files = "/etc/xinetd.*";
filelist = ssh_find_file( file_name:xinetd_files, sock:sock );

if( ! filelist ) {
  set_kb_item( name:"Policy/linux/xinetd/ERROR", value:TRUE );
} else {
  foreach file( filelist ) {
    if( file =~ "xinetd\.conf" )
      parse_xinetd_conf ( filepath:file, socket:sock );
    else
      policy_linux_file_content( socket:sock, file:chomp( file ) );
  }
}

exit( 0 );