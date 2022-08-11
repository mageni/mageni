# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113357");
  script_version("2019-04-25T11:36:15+0000");
  script_tag(name:"last_modification", value:"2019-04-25 11:36:15 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-20 11:13:44 +0100 (Wed, 20 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("rdesktop Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects whether rdesktop is present on the
  target system and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"https://www.rdesktop.org/");

  exit(0);
}

CPE = "cpe:/a:rdesktop:rdesktop:";

include( "ssh_func.inc" );
include( "version_func.inc" );
include( "cpe.inc" );
include( "host_details.inc" );

sock = ssh_login_or_reuse_connection();
if( ! sock ) {
  exit( 0 );
}

paths = find_bin( prog_name: "rdesktop", sock: sock );
foreach bin ( paths )
{
  bin = chomp( bin );
  if( !bin ) continue;
  ver = get_bin_version( full_prog_name: bin, sock: sock,
                         version_argv: "--version",
                         ver_pattern: "Version ([0-9.]+)" );
  if( ! isnull( ver[1] ) )
  {
    set_kb_item( name: "rdesktop/detected", value: TRUE);
    ssh_close_connection();

    register_and_report_cpe(app: "rdesktop",
                            ver: ver[1],
                            base: CPE,
                            expr: "^([0-9.]+)",
                            concluded: ver[0],
                            regPort: 0,
                            regService: "ssh-login",
                            insloc: bin );

  }
}

ssh_close_connection();

exit( 0 );
