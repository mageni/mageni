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
  script_oid("1.3.6.1.4.1.25623.1.0.117281");
  script_version("2021-03-30T09:28:49+0000");
  script_tag(name:"last_modification", value:"2021-03-30 10:22:27 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-30 07:49:07 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache Struts Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Apache Struts.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

full_path_list = ssh_find_file( file_name:"/(pom\.xml|struts2-core-[0-9.]+\.jar)", sock:sock, useregex:TRUE, useextregex:TRUE, regexpar:"$" );
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

    # nb: Don't test for:
    # <groupId>org.apache.struts</groupId>
    # <artifactId>struts2-parent</artifactId>
    # Both are also used in the pom.xml of various Struts plugins...
    if( ! buf || ! concl = egrep( string:buf, pattern:"^\s+(<description>Apache Struts 2</description>|Apache Struts 2 is an elegant, extensible framework|<name>Struts 2</name>)", icase:FALSE ) )
      continue;

    version = "unknown";
    concluded = chomp( concl );

    # <version>2.5.26</version>
    # <version>2.3.37</version>
    # nb:
    # - There is also a previous "<parent>*snip*<version>11</version></parent>" we need
    #   to exclude in the regex (done by expecting a dotted version).
    # - There are also various "<version></version>" strings in the file later (e.g. in
    #   <plugins></plugins> but these should be already excluded because the regex will
    #   return the first found occurrence.
    vers = eregmatch( string:buf, pattern:"( *<version>([0-9.]{4,}[^>]*)</version>)", icase:FALSE );
    if( vers[2] ) {
      version = vers[2];
      concluded += '\n' + vers[1];
    }
  } else {
    type = " (JAR file)";

    version = "unknown";
    vers = eregmatch( string:full_path, pattern:"struts2-core-([0-9.]+)\.jar", icase:FALSE );
    if( vers[1] ) {
      version = vers[1];
      concluded = vers[0];
    }
  }

  set_kb_item( name:"apache/struts/detected", value:TRUE );
  set_kb_item( name:"apache/struts/ssh-login/detected", value:TRUE );
  set_kb_item( name:"apache/struts/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---#" + type );
}

ssh_close_connection();
exit( 0 );
