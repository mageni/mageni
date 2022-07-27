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
  script_oid("1.3.6.1.4.1.25623.1.0.113542");
  script_version("2019-10-21T13:54:30+0000");
  script_tag(name:"last_modification", value:"2019-10-21 13:54:30 +0000 (Mon, 21 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-21 14:53:55 +0200 (Mon, 21 Oct 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("tcpdump Detection (SSH)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Checks whether tcpdump is installed on the target system
  and if so, tries to detect the installed version.");

  script_xref(name:"URL", value:"https://www.tcpdump.org/");

  exit(0);
}

CPE_tcpdump = "cpe:/a:tcpdump:tcpdump:";
CPE_libpcap = "cpe:/a:tcpdump:libpcap:";

include( "host_details.inc" );
include( "ssh_func.inc" );
include( "cpe.inc" );

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

paths = find_file( file_name: "tcpdump", file_path: "/", useregex: TRUE,
                   regexpar: "$", sock: sock );

foreach file ( paths ) {
  file = chomp( file );
  if( ! file ) continue;
  tcpdump_ver = get_bin_version( full_prog_name: file, version_argv: "--version",
                                 ver_pattern: "tcpdump version ([0-9.]+)", sock: sock );

  if( ! isnull( tcpdump_ver[1] ) ) {

    set_kb_item( name: "tcpdump/detected", value: TRUE );

    register_and_report_cpe( app: "tcpdump",
                             ver: tcpdump_ver[1],
                             concluded: tcpdump_ver[0],
                             base: CPE_tcpdump,
                             expr: '([0-9.]+)',
                             insloc: file,
                             regPort: 0,
                             regService: "ssh-login" );
  }

  libpcap_ver = get_bin_version( full_prog_name: file, version_argv: "--version",
                                 ver_pattern: "libpcap version ([0-9.]+)", sock: sock );

  if ( ! isnull( libpcap_ver[1] ) ) {
    set_kb_item( name: "libpcap/detected", value: TRUE );

    register_and_report_cpe( app: "libpcap",
                             ver: libpcap_ver[1],
                             concluded: libpcap_ver[0],
                             base: CPE_libpcap,
                             expr: '([0-9.]+)',
                             insloc: file,
                             regPort: 0,
                             regService: "ssh-login" );
  }
}

exit( 0 );
