# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113864");
  script_version("2022-03-31T08:10:50+0000");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-31 07:40:33 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware Spring Framework (Core) Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of VMware Spring Framework (Core
  component).");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

full_path_list = ssh_find_file( file_name:"/spring[0-9]?-core(-[0-9.x-]+)?\.jar$", sock:sock, useregex:TRUE );
if( ! full_path_list ) {
  ssh_close_connection();
  exit( 0 );
}

port = kb_ssh_transport();

foreach full_path( full_path_list ) {

  full_path = chomp( full_path );
  if( ! full_path )
    continue;

  version = "unknown";
  concluded = "";

  # Default name if downloaded:
  # spring-core-5.3.17.jar
  # but on Debian e.g.:
  # spring3-core-3.x.jar
  # spring3-core.jar
  vers = eregmatch( string:full_path, pattern:"/spring[0-9]?-core.*-([0-9.x]+)\.jar", icase:FALSE );
  if( vers[1] ) {
    version = vers[1];
    concluded = vers[0];
  }

  set_kb_item( name:"vmware/spring/framework/core/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/framework/core/ssh-login/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/framework/core/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + concluded );
}

ssh_close_connection();
exit( 0 );
