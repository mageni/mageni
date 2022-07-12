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
  script_oid("1.3.6.1.4.1.25623.1.0.108578");
  script_version("2019-05-23T06:42:35+0000");
  script_tag(name:"last_modification", value:"2019-05-23 06:42:35 +0000 (Thu, 23 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-16 12:08:23 +0000 (Thu, 16 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OpenSSH Detection (SSH-Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script performs SSH login based detection of a OpenSSH
  installation.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("misc_func.inc");

known_exclusions = make_list(
"/etc/ssh",
"/usr/lib/apt/methods/ssh",
"/etc/init.d/ssh",
"/etc/default/ssh",
"/etc/pam.d/sshd" );

known_locations = make_list(
"/usr/bin/ssh",
"/usr/local/bin/ssh",
"/usr/sbin/sshd",
"/usr/local/sbin/sshd" );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = kb_ssh_transport();

# nb: find_file() instead of find_bin() is used here so that we're able to use a regex
path_list = find_file( file_name:"sshd", sock:sock, extregex:TRUE, regexpar:"?$", file_path:"/" );
if( ! path_list || ! is_array( path_list ) ) {
  ssh_close_connection();
  exit( 0 );
}

# Add some common known file locations.
# nb: The sbin ones are added here as mlocate might not find these but the
# binaries are still accessible for version gathering in most situations.
foreach known_location( known_locations ) {
  if( ! in_array( search:known_location, array:path_list, part_match:FALSE ) )
    path_list = make_list( path_list, known_location );
}

foreach path( path_list ) {

  path = chomp( path );
  if( ! path )
    continue;

  if( in_array( search:path, array:known_exclusions, part_match:FALSE ) )
    continue;

  # ssh -V examples:
  # OpenSSH_4.7p1 Debian-8ubuntu1, OpenSSL 0.9.8g 19 Oct 2007
  # OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017
  # OpenSSH_7.2p2, OpenSSL 1.0.2k-fips  26 Jan 2017
  # OpenSSH_7.7, LibreSSL 2.7.2
  # OpenSSH_6.0p1 Debian-4+deb7u7, OpenSSL 1.0.1t  3 May 2016
  # OpenSSH_6.7p1 Debian-5+deb8u3, OpenSSL 1.0.1t  3 May 2016
  # OpenSSH_7.4p1 Debian-10+deb9u4, OpenSSL 1.0.2q  20 Nov 2018
  #
  # nb: sshd doesn't support a -V parameter but is printing out the same version pattern above with a prepended "sshd: illegal option -- V" and a appended "usage: sshd" message
  vers = get_bin_version( full_prog_name:path, sock:sock, version_argv:"-V", ver_pattern:'OpenSSH_([.a-zA-Z0-9]+)[- ]?[^\r\n]+' );
  if( vers[1] ) {
    version = vers[1];
    found = TRUE;

    if( "usage: sshd" >< vers[ max_index( vers ) - 1] )
      type = "Server";
    else
      type = "Client";

    set_kb_item( name:"openssh/ssh-login/" + port + "/installs", value:"0#---#" + path + "#---#" + version + "#---#" + vers[0] + "#---#" + type );
  }
}

if( found ) {
  set_kb_item( name:"openssh/detected", value:TRUE );
  set_kb_item( name:"openssh/ssh-login/detected", value:TRUE );
  set_kb_item( name:"openssh/ssh-login/port", value:port );
}

exit( 0 );