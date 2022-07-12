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
  script_oid("1.3.6.1.4.1.25623.1.0.113885");
  script_version("2022-04-11T07:00:07+0000");
  script_tag(name:"last_modification", value:"2022-04-11 10:12:33 +0000 (Mon, 11 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-06 08:06:40 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware Spring Boot Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of VMware Spring Boot (and its
  components).");

  script_tag(name:"vuldetect", value:"To get the product version, the script logs in via SSH and
  searches for the VMware Spring Boot JAR files on the filesystem.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");
include("spring_prds.inc");

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

if( ! comp_list = spring_boot_comp_list() )
  exit( 0 );

if( ! comp_pattern = list2or_regex( list:comp_list ) )
  exit( 0 );

# nb: regex is slightly different than the one of the Spring Framework detection because we don't
# have any fixed "core" component here.
file_pattern = "/spring-boot-?" + comp_pattern + "?([0-9.A-Zx-]+)?\.jar$";

if( ! full_path_list = ssh_find_file( file_name:file_pattern, sock:sock, useregex:TRUE ) ) {
  ssh_close_connection();
  exit( 0 );
}

port = kb_ssh_transport();

foreach full_path( full_path_list ) {

  if( ! full_path = chomp( full_path ) )
    continue;

  # Default names of files if downloaded are e.g.:
  #
  # spring-boot-2.2.13.RELEASE.jar
  # spring-boot-2.6.5.jar
  # spring-boot-starter-web-2.6.5.jar
  # spring-boot-starter-webflux-2.6.5.jar
  #

  # Just another fallback if ssh_find_file() is returning something unexpected.
  if( ! eregmatch( string:full_path, pattern:file_pattern, icase:FALSE ) )
    continue;

  comp = eregmatch( string:full_path, pattern:"/spring-boot-" + comp_pattern + "([0-9.A-Zx-]+)?\.jar$", icase:FALSE );

  # nb: We're calling the default spring-boot-2.6.5.jar file "core" component for a better/easier
  # handling in the consolidation...
  if( ! comp[1] )
    component = "core";
  else
    component = comp[1];

  version   = "unknown";
  concluded = ""; # nb: Just overwriting a possible previously defined string
  comp_key  = tolower( component );

  vers = eregmatch( string:full_path, pattern:"/spring-boot-" + comp_pattern + "?-?([0-9.x]+)(\.RELEASE)?\.jar$", icase:FALSE );
  if( vers[2] ) {
    version = vers[2];
    concluded = vers[0];
  }

  set_kb_item( name:"vmware/spring/boot/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/boot/ssh-login/detected", value:TRUE );

  set_kb_item( name:"vmware/spring/boot/" + comp_key + "/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/boot/" + comp_key + "/ssh-login/detected", value:TRUE );

  set_kb_item( name:"vmware/spring/boot/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---#" + component );
}

ssh_close_connection();
exit( 0 );
