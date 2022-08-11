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
  script_version("2022-04-04T13:16:12+0000");
  script_tag(name:"last_modification", value:"2022-04-05 10:21:53 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-31 07:40:33 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware Spring Framework Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of the VMware Spring Framework (and
  its components).");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");
include("spring_prds.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

comp_pattern = spring_framework_comp_regex();

full_path_list = ssh_find_file( file_name:"/spring[0-9]?-" + comp_pattern + "[-.].*\.jar$", sock:sock, useregex:TRUE );
if( ! full_path_list ) {
  ssh_close_connection();
  exit( 0 );
}

port = kb_ssh_transport();

foreach full_path( full_path_list ) {

  full_path = chomp( full_path );
  if( ! full_path )
    continue;

  # Default names of files if downloaded are e.g.:
  #
  # spring-core-5.3.17.jar
  # spring-webflux-5.3.17.jar
  # spring-webflux-5.3.17.jar
  #
  # Included in e.g. Struts2:
  #
  # struts-2.3.37/lib/spring-core-3.0.5.RELEASE.jar
  #
  # but on Debian e.g.:
  #
  # spring3-core-3.x.jar
  # spring3-core.jar
  # spring3-aop-3.x.jar
  # spring3-aop.jar
  # spring3-web-3.x.jar
  # spring3-web.jar
  #
  # or also (at e.g. /usr/share/maven-repo/org/springframework/spring-oxm/4.3.22.RELEASE/):
  #
  # spring-oxm-4.3.22.RELEASE.jar
  # spring-web-4.3.22.RELEASE.jar
  #
  # or even (at e.g. /usr/share/maven-repo/org/springframework/spring-aop/debian/):
  #
  # spring-aop-debian.jar
  #
  comp = eregmatch( string:full_path, pattern:"/spring[0-9]?-" + comp_pattern + "[-.].*\.jar$", icase:FALSE );

  # Just another fallback if ssh_find_file() is returning something unexpected.
  if( ! comp[1] )
    continue;

  version   = "unknown";
  concluded = "";
  component = comp[1];
  comp_key  = tolower( component );

  vers = eregmatch( string:full_path, pattern:"/spring[0-9]?-" + comp_pattern + "-([0-9.x]+)(\.RELEASE)?\.jar$", icase:FALSE );
  if( vers[2] ) {
    version = vers[2];
    concluded = vers[0];
  }

  set_kb_item( name:"vmware/spring/framework/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/framework/ssh-login/detected", value:TRUE );

  set_kb_item( name:"vmware/spring/framework/" + comp_key + "/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/framework/" + comp_key + "/ssh-login/detected", value:TRUE );

  set_kb_item( name:"vmware/spring/framework/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---#" + component );
}

ssh_close_connection();
exit( 0 );
