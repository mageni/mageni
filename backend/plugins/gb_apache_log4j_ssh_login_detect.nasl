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
  script_oid("1.3.6.1.4.1.25623.1.0.117821");
  script_version("2021-12-11T16:08:20+0000");
  script_tag(name:"last_modification", value:"2021-12-11 16:08:20 +0000 (Sat, 11 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-11 15:08:22 +0000 (Sat, 11 Dec 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache Log4j Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Apache Log4j.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

full_path_list = ssh_find_file( file_name:"/(pom\.xml|log4j(-core)?(-[0-9.x-]+)?\.jar)$", sock:sock, useregex:TRUE );
if( ! full_path_list ) {
  ssh_close_connection();
  exit( 0 );
}

port = kb_ssh_transport();

foreach full_path( full_path_list ) {

  full_path = chomp( full_path );
  if( ! full_path )
    continue;

  if( "/pom.xml" >< full_path ) {
    type = " (Sources)";
    buf = ssh_cmd( socket:sock, cmd:"cat " + full_path );

    if( ! buf || ! concl = egrep( string:buf, pattern:"^\s+(<description>(The )?Apache Log4j( Implementation)?( [0-9.]+)?</description>|<name>Apache Log4j( Core)?</name>)", icase:FALSE ) )
      continue;

    version = "unknown";
    concluded = chomp( concl );

    vers = eregmatch( string:buf, pattern:"( *<version>([0-9.]+[^>]*)</version>)", icase:FALSE );
    if( vers[2] ) {
      version = vers[2];
      concluded += '\n' + vers[1];
    }
  } else {
    type = " (JAR file)";

    version = "unknown";
    concluded = "";

    # log4j-1.2-1.2.17.jar
    # log4j-1.2.jar
    # log4j-1.2.17.jar
    # log4j-1.2.17.pom
    # log4j-1.2.x.jar
    # log4j-1.2.x.pom
    # log4j-core-2.7.jar
    # log4j-core.jar
    # log4j-core-2.7.jar
    # log4j-core-2.7.pom
    # log4j-2.7.pom
    # log4j-core-2.11.1.jar
    # log4j-core-java9-2.11.1.pom
    # log4j-core-java9-debian.pom
    # log4j-core-2.11.1.jar
    # log4j-core-2.11.1.pom
    # log4j-2.11.1.pom
    # log4j-debian.pom
    # log4j-core-2.13.3.jar
    # log4j-core-java9-2.13.3.pom
    # log4j-2.13.3.pom
    # log4j-core-2.13.3.jar
    # log4j-core-2.13.3.pom
    #
    # nb: As some of the files examples above contains e.g. 1.2-1.2.17 and we only want to catch
    # the last version so we're using a more strict regex pattern here enforcing a version having
    # three number parts.
    vers = eregmatch( string:full_path, pattern:"/log4j.*-([0-9.x]+)\.jar", icase:FALSE );
    if( vers[1] ) {
      version = vers[1];
      concluded = vers[0];
    }

    # nb: If we didn't get the version from the file name or only a short one like "1.2" we're
    # trying to get it from a possible existing .pom file (exists on e.g. Debian).
    if( version == "unknown" || version =~ "^[0-9]+\.[0-9]+(\.x)?$" ) {
      _full_path = ereg_replace( string:full_path, pattern:"\.jar$", replace:".pom" );
      if( _full_path ) {
        buf = ssh_cmd( socket:sock, cmd:"cat " + _full_path );
        if( concl = egrep( string:buf, pattern:"^\s+(<description>(The )?Apache Log4j( Implementation)?( [0-9.]+)?</description>|<name>Apache Log4j( Core)?</name>)", icase:FALSE ) ) {

          if( concluded )
            concluded += '\n';
          concluded += chomp( concl );
          concluded += '\n' + _full_path;

          # <version>2.7</version>
          # <version>2.15.0</version>
          # <version>1.2.x</version>
          vers = eregmatch( string:buf, pattern:"( *<version>([0-9.]+[^>]*)</version>)", icase:FALSE );
          if( vers[2] ) {
            version = vers[2];
            concluded += '\n' + vers[1];
          }
        }
      }
    }
  }

  set_kb_item( name:"apache/log4j/detected", value:TRUE );
  set_kb_item( name:"apache/log4j/ssh-login/detected", value:TRUE );
  set_kb_item( name:"apache/log4j/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---#" + type );
}

ssh_close_connection();
exit( 0 );