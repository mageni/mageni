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
  script_oid("1.3.6.1.4.1.25623.1.0.112868");
  script_version("2021-03-02T08:22:06+0000");
  script_tag(name:"last_modification", value:"2021-03-02 12:14:25 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-02-26 09:37:11 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Dropbear Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Dropbear.");

  exit(0);
}

include( "ssh_func.inc" );
include( "list_array_func.inc" );
include( "host_details.inc" );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = kb_ssh_transport();

paths = ssh_find_file( file_name: "/dbclient", sock: sock, useregex: TRUE, regexpar: "$" );

found = FALSE;

foreach bin( paths ) {

  bin = chomp( bin );
  if( ! bin )
    continue;

  # Dropbear v2018.76
  # Dropbear client v0.48
  # nb: Older dbclient versions doesn't support -V but we can still grab the version from the help banner.
  ver = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "-V", ver_pattern: "Dropbear (client )?v([0-9.]+)" );
  if( ! isnull( ver[2] ) ) {
    version = ver[2];
    found = TRUE;

    set_kb_item( name: "dropbear_ssh/ssh-login/" + port + "/installs", value: "0#---#" + bin + "#---#" + version + "#---#" + ver[0] );
  }
}

if( found ) {
  set_kb_item( name: "dropbear_ssh/detected", value: TRUE );
  set_kb_item( name: "dropbear_ssh/ssh-login/detected", value: TRUE );
  set_kb_item( name: "dropbear_ssh/ssh-login/port", value: port );
}

ssh_close_connection();
exit( 0 );
