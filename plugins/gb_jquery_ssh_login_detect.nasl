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
  script_oid("1.3.6.1.4.1.25623.1.0.150657");
  script_version("2021-06-08T12:20:37+0000");
  script_tag(name:"last_modification", value:"2021-06-11 10:19:43 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-02 14:44:56 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("jQuery Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of jQuery.");

  exit(0);
}

include( "ssh_func.inc" );
include( "list_array_func.inc" );
include( "host_details.inc" );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = kb_ssh_transport();

files = ssh_find_file( file_name:"/jquery[-.]?([0-9.]+)?(\.min|\.slim|\.slim\.min)?\.js", useextregex:TRUE, regexpar:"$", sock:sock );

found = FALSE;

foreach file( files ) {
  file = chomp( file );
  if( ! file )
    continue;

  # jquery-1.11.2.min.js
  vers = eregmatch( string:file, pattern:"jquery[-.]?([0-9.]+)?(\.min|\.slim|\.slim\.min)?\.js" );
  if( ! vers[1] ) {
    content = ssh_cmd( socket:sock, cmd:"cat " + file );
    # version="3.1.1"
    vers = eregmatch( string:content, pattern:'version\\s*=\\s*"?([0-9.]+)' );
  }

  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    found = TRUE;

    set_kb_item( name:"jquery/ssh-login/" + port + "/installs", value:"0#---#" + file + "#---#" + version + "#---#" + vers[0] );

  }
}

if( found ) {
  set_kb_item( name:"jquery/detected", value:TRUE );
  set_kb_item( name:"jquery/ssh-login/detected", value:TRUE );
}

ssh_close_connection();
exit( 0 );
