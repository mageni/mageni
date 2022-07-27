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
  script_oid("1.3.6.1.4.1.25623.1.0.113789");
  script_version("2021-02-22T14:03:27+0000");
  script_tag(name:"last_modification", value:"2021-02-23 12:20:55 +0000 (Tue, 23 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-22 13:57:55 +0100 (Mon, 22 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("SQLite Detection (SSH)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");


  script_tag(name:"summary", value:"Checks whether sqlite is present on the target system and,
  if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"https://www.sqlite.org/index.html");

  exit(0);
}

CPE = "cpe:/a:sqlite:sqlite:";

include( "cpe.inc" );
include( "ssh_func.inc" );
include( "host_details.inc" );
include( "list_array_func.inc" );
include( "port_service_func.inc" );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = ssh_get_port( default: 22 );

v2_paths = ssh_find_bin( prog_name: "sqlite", sock: sock );
v3_paths = ssh_find_bin( prog_name: "sqlite3", sock: sock );
paths = make_list_unique( v2_paths, v3_paths );

foreach bin( paths )
{
  bin = chomp(bin);
  if( ! bin)
    continue;

  ver = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: ":memory: 'select sqlite_version();'", ver_pattern: "([0-9.]+)" );

  if( ver[1] ) {
    version = ver[1];

    set_kb_item( name: "sqlite/detected", value: TRUE );
    set_kb_item( name: "sqlite/ssh/detected", value: TRUE );
    set_kb_item( name: "sqlite/version", value: version );

    register_and_report_cpe( app: "SQLite",
                             ver: version,
                             concluded: ver[0],
                             base: CPE,
                             expr: "([0-9.]+)",
                             insloc: bin,
                             regPort: 0,
                             regService: "ssh" );
  }
}

ssh_close_connection();

exit( 0 );
