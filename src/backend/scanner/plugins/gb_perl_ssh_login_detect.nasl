# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108503");
  script_version("2021-07-14T14:10:02+0000");
  script_tag(name:"last_modification", value:"2021-07-14 14:10:02 +0000 (Wed, 14 Jul 2021)");
  script_tag(name:"creation_date", value:"2018-12-10 09:46:38 +0100 (Mon, 10 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Perl Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Perl.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = kb_ssh_transport();

full_path_list = ssh_find_file( file_name:"/perl5?$", sock:sock, useregex:TRUE );
if( ! full_path_list ) {
  ssh_close_connection();
  exit( 0 );
}

found = FALSE;

foreach full_path( full_path_list ) {

  full_path = chomp( full_path );
  if( ! full_path )
    continue;

  # This is perl 5, version 20, subversion 2 (v5.20.2) built for x86_64-linux-gnu-thread-multi
  # This is perl 5, version 28, subversion 1 (v5.28.1) built for x86_64-linux-gnu-thread-multi
  # This is perl, v5.8.8 built for i486-linux-gnu-thread-multi
  vers = ssh_get_bin_version( full_prog_name:full_path, sock:sock, version_argv:"-v", ver_pattern:"This is perl(, v| [0-9]+, version [0-9]+, subversion [0-9]+ \(v)([0-9.]+)" );

  if( vers[2] ) {
    version = vers[2];
    found = TRUE;

    set_kb_item( name:"perl/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + vers[0] );
  }
}

if( found ) {
  set_kb_item( name:"perl/detected", value:TRUE );
  set_kb_item( name:"perl/ssh-login/detected", value:TRUE );
  set_kb_item( name:"perl/ssh-login/port", value:port );
}

ssh_close_connection();
exit( 0 );