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
  script_oid("1.3.6.1.4.1.25623.1.0.112805");
  script_version("2020-08-12T09:05:13+0000");
  script_tag(name:"last_modification", value:"2020-08-12 10:28:50 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-11 11:26:21 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Evince Detection (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH based detection of Evince.");

  script_xref(name:"URL", value:"https://wiki.gnome.org/Apps/Evince");

  exit(0);
}

CPE = "cpe:/a:gnome:evince:";

include( "ssh_func.inc" );
include( "cpe.inc" );
include( "list_array_func.inc" );
include( "host_details.inc" );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

paths = make_list();
foreach file( make_list( "evince" ) ) {
  _paths = ssh_find_bin( prog_name: file, sock: sock );
  if( _paths )
    paths = make_list_unique( paths, _paths );
}

foreach bin( paths ) {

  bin = chomp( bin );
  if( ! bin )
    continue;

  ver = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "--version", ver_pattern: "GNOME Document Viewer ([0-9.]+)" );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    set_kb_item( name: "gnome/evince/detected", value: TRUE );

    register_and_report_cpe( app: "Evince",
                             ver: version,
                             concluded: ver[0],
                             base: CPE,
                             expr: "([0-9.]+)",
                             insloc: bin,
                             regPort: 0,
                             regService: "ssh-login" );
  }
}

ssh_close_connection();
exit( 0 );
