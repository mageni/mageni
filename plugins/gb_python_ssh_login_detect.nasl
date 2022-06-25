# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113560");
  script_version("2021-01-29T14:50:46+0000");
  script_tag(name:"last_modification", value:"2021-02-05 17:59:24 +0000 (Fri, 05 Feb 2021)");
  script_tag(name:"creation_date", value:"2019-11-11 11:11:11 +0200 (Mon, 11 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Python Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Python.");

  script_xref(name:"URL", value:"https://www.python.org/");

  exit(0);
}

include( "ssh_func.inc" );
include( "list_array_func.inc" );
include( "host_details.inc" );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = kb_ssh_transport();

paths = make_list_unique( ssh_find_bin( prog_name: "python", sock: sock ), ssh_find_bin( prog_name: "python3", sock: sock ) );

found = FALSE;

foreach bin( paths ) {

  bin = chomp( bin );
  if( !bin ) continue;
  ver = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "--version", ver_pattern: "Python ([0-9.]+)" );

  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    found = TRUE;

    set_kb_item( name:"python/ssh-login/" + port + "/installs", value:"0#---#" + bin + "#---#" + version + "#---#" + ver[0] );
  }
}

if( found ) {
  set_kb_item( name:"python/detected", value: TRUE );
  set_kb_item( name:"python/ssh-logins/detected", value: TRUE );
  set_kb_item( name:"python/ssh-login/port", value: port );
}

ssh_close_connection();
exit( 0 );
