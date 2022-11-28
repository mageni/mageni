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
  script_oid("1.3.6.1.4.1.25623.1.0.104437");
  script_version("2022-11-25T12:26:37+0000");
  script_tag(name:"last_modification", value:"2022-11-25 12:26:37 +0000 (Fri, 25 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-24 14:27:54 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache Commons Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Apache Commons (and its
  components).");

  script_tag(name:"vuldetect", value:"To get the product version, the script logs in via SSH and
  searches for the Apache Commons JAR files on the filesystem.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");
include("apache_prds.inc");

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

if( ! comp_list = apache_commons_comp_list() )
  exit( 0 );

if( ! comp_pattern = list2or_regex( list:comp_list ) )
  exit( 0 );

file_pattern = "/commons-" + comp_pattern + "-?([0-9.]+)?\.jar$";

if( ! full_path_list = ssh_find_file( file_name:file_pattern, sock:sock, useregex:TRUE ) ) {
  ssh_close_connection();
  exit( 0 );
}

port = kb_ssh_transport();

foreach full_path( full_path_list ) {

  if( ! full_path = chomp( full_path ) )
    continue;

  # e.g. on Debian (libcommons-collections3-java and libcommons-text-java):
  # commons-collections3-3.2.2.jar
  # commons-collections3.jar
  # commons-collections-3.2.2.jar
  # commons-collections-3.x.jar
  # commons-text-1.10.0.jar
  # commons-text.jar
  #
  # or when downloaded from Maven Central directly (similar to the ones above):
  #
  # commons-collections4-4.4.jar
  # commons-weaver-normalizer-2.0.jar

  # Just another fallback if ssh_find_file() is returning something unexpected.
  if( ! eregmatch( string:full_path, pattern:file_pattern, icase:FALSE ) )
    continue;

  version = "unknown";

  comp_nd_vers = eregmatch( string:full_path, pattern:"/commons-" + comp_pattern + "-?([0-9.]+)?\.jar$", icase:FALSE );
  concluded = comp_nd_vers[0];

  # nb: Should always match but checking it anyway for best practice reasons...
  if( comp_nd_vers[1] ) {
    component = comp_nd_vers[1];
    # nb: We're dropping e.g. the "3" in "commons-collections3" to match what's used by the NVD
    if( component != "rdf-rdf4j" )
      component = ereg_replace( string:component, pattern:"([0-9])", replace:"" );
  }

  if( comp_nd_vers[2] )
    version = comp_nd_vers[2];

  comp_key = tolower( component );

  set_kb_item( name:"apache/commons/detected", value:TRUE );
  set_kb_item( name:"apache/commons/ssh-login/detected", value:TRUE );

  set_kb_item( name:"apache/commons/" + comp_key + "/detected", value:TRUE );
  set_kb_item( name:"apache/commons/" + comp_key + "/ssh-login/detected", value:TRUE );

  set_kb_item( name:"apache/commons/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---#" + component );
}

ssh_close_connection();
exit( 0 );
