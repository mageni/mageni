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
  script_oid("1.3.6.1.4.1.25623.1.0.117279");
  script_version("2021-03-29T11:09:57+0000");
  script_tag(name:"last_modification", value:"2021-03-30 10:22:27 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-29 10:21:42 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("rpcbind Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://sourceforge.net/projects/rpcbind/");

  script_tag(name:"summary", value:"SSH login-based detection of rpcbind.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

# nb: On package based installs the file is placed in /sbin which isn't necessarily
# indexed by mlocate so we're just adding the file here to be sure to catch it. Even if
# the binary is located in /sbin we can call the test command below as an unprivileged user.
# /usr/sbin and /usr/local/sbin was added just to be sure.
full_path_list = make_list( "/sbin/rpcbind", "/usr/sbin/rpcbind", "/usr/local/sbin/rpcbind" );

found_path_list = ssh_find_file( file_name:"/rpcbind", sock:sock, useregex:TRUE, regexpar:"$" );
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

foreach full_path( full_path_list ) {

  full_path = chomp( full_path );
  if( ! full_path )
    continue;

  # nb: All rpcbind (up to the most recent 1.2.5) doesn't support any "version output"
  # command so we need to pass an invalid parameter to trigger the following output
  # variants shown below (if "-test" is passed).
  #
  # rpcbind 0.2.0:
  # rpcbind: invalid option -- 't'
  # usage: rpcbind [-adhilswf]
  #
  # rpcbind 1.2.5 (one new "r" parameter got added but the other output is the same):
  # rpcbind: invalid option -- 't'
  # usage: rpcbind [-adhilswfr]

  buf = ssh_cmd( socket:sock, cmd:full_path + " -test" );
  if( ! buf || "rpcbind: invalid option " >!< buf || "usage: rpcbind " >!< buf )
    continue;

  version = "unknown";
  concluded = "";
  extra = "";

  set_kb_item( name:"rpcbind/detected", value:TRUE );
  set_kb_item( name:"rpcbind/ssh-login/detected", value:TRUE );

  # nb: As previously explained there is no "version output" command in rpcbind available.
  # But some binaries are exposing their version if examined via "strings" like e.g.:
  #
  # SLES 15 SP2: rpcbind-0.2.3-5.9.2.x86_64.debug
  # EulerOS 2.0 SP9: rpcbind-1.2.5-4.h2.eulerosv2r9.x86_64.debug
  # CentOS 8: rpcbind-1.2.5-7.el8.x86_64.debug

  cmd = "strings " + full_path;
  # nb: We're returning the linux errors here because the "strings" results are containing
  # some of the pattern checked in "ssh_cmd" in some cases.
  buf = ssh_cmd( socket:sock, cmd:cmd, return_errors:TRUE, return_linux_errors_only:TRUE );
  if( buf && concl = egrep( string:buf, pattern:"^rpcbind-[0-9.]{3,}", icase:FALSE ) ) {
    concl = chomp( concl );
    concluded = concl + '\n' + "via '" + cmd + "' command.";
    vers = eregmatch( string:concl, pattern:"^rpcbind-([0-9.]+)", icase:FALSE );
    if( vers[1] )
      version = vers[1];
  }

  if( version == "unknown" )
    extra = "rpcbind version extraction only possible via 'strings' command. If the command isn't available on the target system please install it.";

  register_and_report_cpe( app:"rpcbind", ver:version, base:"cpe:/a:rpcbind_project:rpcbind:", expr:"([0-9.]+)", regPort:0, insloc:full_path, concluded:concluded, regService:"ssh-login", extra:extra );
}

ssh_close_connection();
exit( 0 );
