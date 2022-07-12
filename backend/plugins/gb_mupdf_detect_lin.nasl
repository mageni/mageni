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
  script_oid("1.3.6.1.4.1.25623.1.0.112804");
  script_version("2020-08-12T09:29:49+0000");
  script_tag(name:"last_modification", value:"2020-08-12 10:28:50 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-11 07:56:12 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("MuPDF Detection (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH based detection of MuPDF.");

  script_xref(name:"URL", value:"https://mupdf.com/");

  exit(0);
}

CPE = "cpe:/a:artifex:mupdf:";

include( "ssh_func.inc" );
include( "cpe.inc" );
include( "list_array_func.inc" );
include( "host_details.inc" );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

paths = make_list();
foreach file( make_list( "mupdf", "mupdf-x11", "mupdf-gl" ) ) {
  # nb: On at least Debian mupdf-x11 is located in /usr/lib/mupdf/mupdf-x11
  # so we can't / shouldn't use ssh_find_bin() here.
  _paths = ssh_find_file( file_name: file, useregex: TRUE, regexpar: "$", sock: sock );
  if( _paths )
    paths = make_list_unique( paths, _paths );
}

foreach bin( paths ) {

  bin = chomp( bin );
  if( ! bin )
    continue;

  # nb: mupdf exists either as a pure bash script (at least on Debian) or binary. As we only want to catch and confirm the latter, a parameter needs to be sent in addition.
  # However, as of now mupdf only accepts three parameters "-a", "-r", "-p" and doesn't work with common parameters like "--version" or "-h", so a non-existent parameter is being sent.
  # Only the binary (which we want to detect) will then return the desired pattern. The bash script (which we don't want to detect) will return an error message.
  bin_check = ssh_cmd( socket: sock, cmd: bin + " -0" );
  if( egrep( pattern: "^usage: mupdf", string: bin_check ) ) {

    set_kb_item( name: "artifex/mupdf/detected", value: TRUE );

    version = "unknown";
    concl = chomp( bin_check );

    # Since the version is not being exposed through a command line parameter, it has to be extracted from the contents of the binary.
    # MuPDF 1.7a
    # MuPDF 1.7
    # MuPDF had a few "a" releases: https://mupdf.com/release_history.html
    if( vers_grep = ssh_get_bin_version( full_prog_name: "strings", version_argv: bin, ver_pattern: "MuPDF ([0-9.a]+)" , sock: sock ) ) {
      if( vers_grep[1] ) {
        version = vers_grep[1];
        concl = vers_grep[0] + " from binary version extraction via: strings " + bin + " | egrep 'MuPDF ([0-9.a]+)'";
      }
    }

    register_and_report_cpe( app: "MuPDF",
                             ver: version,
                             concluded: concl,
                             base: CPE,
                             expr: "([0-9.a]+)",
                             insloc: bin,
                             regPort: 0,
                             regService: "ssh-login" );
  }
}

ssh_close_connection();
exit( 0 );
