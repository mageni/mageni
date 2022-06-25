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
  script_oid("1.3.6.1.4.1.25623.1.0.108939");
  script_version("2020-10-08T10:45:55+0000");
  script_tag(name:"last_modification", value:"2020-10-09 10:01:41 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-08 09:07:41 +0000 (Thu, 08 Oct 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("dmidecode Detection (SSH-Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.nongnu.org/dmidecode/");

  script_tag(name:"summary", value:"SSH login based detection of dmidecode.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

full_path_list = ssh_find_file( file_name:"/dmidecode", sock:sock, useregex:TRUE, regexpar:"/dmidecode$" );
if( ! full_path_list ) {
  ssh_close_connection();
  exit( 0 );
}

foreach full_path( full_path_list ) {

  full_path = chomp( full_path );
  if( ! full_path )
    continue;

  # nb: Not using ssh_get_bin_version() is expected because we want to evaluate the permissions later.
  # We're also not passing the --version parameter to exactly trigger the permission messages evaluated there.
  res = ssh_cmd( socket:sock, cmd:full_path, return_errors:TRUE, return_linux_errors_only:TRUE );
  res = chomp( res );
  if( ! res )
    continue;

  # e.g. (nb: the "#" is prepended in the output):
  # # dmidecode 2.11
  # # dmidecode 3.2
  vers = eregmatch( string:res, pattern:"^# dmidecode ([0-9]+\.[0-9.]+)", icase:FALSE );
  if( vers[1] ) {

    version = vers[1];

    if( "/dev/mem: Permission denied" >< res &&
        res =~ "/sys/firmware/dmi/tables.+: Permission denied" )
      set_kb_item( name:"dmidecode/ssh-login/no_permissions", value:TRUE );
    else
      set_kb_item( name:"dmidecode/ssh-login/full_permissions", value:TRUE );

    set_kb_item( name:"dmidecode/detected", value:TRUE );
    set_kb_item( name:"dmidecode/ssh-login/detected", value:TRUE );
    register_and_report_cpe( app:"dmidecode", ver:version, base:"cpe:/a:nongnu:dmidecode:", expr:"([0-9.]+)", regPort:0, insloc:full_path, concluded:vers[0], regService:"ssh-login" );
  }
}

ssh_close_connection();
exit( 0 );
