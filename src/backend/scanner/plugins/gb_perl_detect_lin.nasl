###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_detect_lin.nasl 12737 2018-12-10 10:25:57Z cfischer $
#
# Perl Detection (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108503");
  script_version("$Revision: 12737 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 11:25:57 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-10 09:46:38 +0100 (Mon, 10 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Perl Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects via SSH if Perl is installed on the target
  host.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

full_path_list = find_bin( prog_name:"perl", sock:sock );
if( ! full_path_list ) {
  ssh_close_connection();
  exit( 0 );
}

foreach full_path( full_path_list ) {

  full_path = chomp( full_path );
  if( ! full_path )
    continue;

  # This is perl 5, version 20, subversion 2 (v5.20.2) built for x86_64-linux-gnu-thread-multi
  # This is perl 5, version 28, subversion 1 (v5.28.1) built for x86_64-linux-gnu-thread-multi
  # This is perl, v5.8.8 built for i486-linux-gnu-thread-multi
  vers = get_bin_version( full_prog_name:full_path, sock:sock, version_argv:"-v", ver_pattern:"This is perl(, v| [0-9]+, version [0-9]+, subversion [0-9]+ \(v)([0-9.]+)" );

  if( vers[2] ) {
    version = vers[2];
    set_kb_item( name:"perl/linux/detected", value:TRUE );
    register_and_report_cpe( app:"Perl", ver:version, base:"cpe:/a:perl:perl:", expr:"([0-9.]+)", regPort:0, insloc:full_path, concluded:vers[0], regService:"ssh-login" );
  }
}

ssh_close_connection();
exit( 0 );