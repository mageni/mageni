# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117276");
  script_version("2021-03-26T10:02:15+0000");
  script_tag(name:"last_modification", value:"2021-03-29 10:41:25 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-26 07:12:17 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dnsmasq Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Dnsmasq.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

# nb: On package based installs the file is placed in /usr/sbin which isn't necessarily
# indexed by mlocate so we're just adding the file here to be sure to catch it. Even if
# the binary is located in /usr/sbin we can call the -v command as an unprivileged user.
# /usr/local/sbin was added just to be sure.
full_path_list = make_list( "/usr/sbin/dnsmasq", "/usr/local/sbin/dnsmasq" );

found_path_list = ssh_find_file( file_name:"/dnsmasq", sock:sock, useregex:TRUE, regexpar:"$" );
if( found_path_list ) {

  # nb: Some special handling because ssh_find_file() is currently returning the binaries
  # with trailing newlines and making the list "unique" wouldn't work in this case.
  foreach found_path( found_path_list ) {
    found_path = chomp( found_path );
    if( ! found_path )
      continue;

    full_path_list = make_list_unique( full_path_list, found_path );
  }
}

port = kb_ssh_transport();

foreach full_path( full_path_list ) {

  # Dnsmasq version 2.78  Copyright (c) 2000-2017 Simon Kelley -> SLES15 SP2
  # Dnsmasq version 2.76  Copyright (c) 2000-2016 Simon Kelley -> CentOS 7
  # Dnsmasq version 2.81  Copyright (c) 2000-2020 Simon Kelley -> EulerOS 2.0 SP9
  # Dnsmasq version 2.84rc2  Copyright (c) 2000-2021 Simon Kelley -> Debian bullseye/sid

  vers = ssh_get_bin_version( full_prog_name:full_path, sock:sock, version_argv:"-v", ver_pattern:"Dnsmasq version ([0-9.]+(rc[0-9]+)?)" );
  if( ! vers || ! vers[1] )
    continue;

  version = vers[1];
  concluded = vers[max_index(vers) - 1];

  set_kb_item( name:"thekelleys/dnsmasq/detected", value:TRUE );
  set_kb_item( name:"thekelleys/dnsmasq/ssh-login/detected", value:TRUE );
  set_kb_item( name:"thekelleys/dnsmasq/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + concluded );
}

ssh_close_connection();
exit( 0 );
