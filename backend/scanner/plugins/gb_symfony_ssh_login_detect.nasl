###############################################################################
# OpenVAS Vulnerability Test
#
# Sensiolabs Symfony Detection (SSH-Login)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107324");
  script_version("2019-05-23T07:09:57+0000");
  script_tag(name:"last_modification", value:"2019-05-23 07:09:57 +0000 (Thu, 23 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-26 16:20:53 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sensiolabs Symfony Detection (SSH-Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script performs SSH login based detection of a Sensiolabs Symfony
  installation.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

known_path = 'vendor/symfony/symfony/src/Symfony/Component/HttpKernel';
path_list = ssh_cmd( cmd:'find / -path \\*' + known_path + ' 2>/dev/null', socket:sock );
if( ! path_list )
  exit( 0 );

port = kb_ssh_transport();

foreach path( split( path_list ) ) {

  path = ereg_replace( string:path, pattern:'[\r\n]', replace:'' );
  version_text = ssh_cmd( cmd:'grep "const VERSION =" ' + path + '/Kernel.php', socket:sock );
  if( ! version_text )
    continue;

  version_text = ereg_replace( string:version_text, pattern:'^[ ]+', replace:'' );
  vers = eregmatch( string:version_text, pattern:'([0-9.]+)' );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    location = ereg_replace( string:path, pattern:known_path, replace:'' );
    found = TRUE;
    set_kb_item( name:"symfony/ssh-login/" + port + "/installs", value:"0#---#" + location + "#---#" + version + "#---#" + version_text + "#---#" + path + '/Kernel.php' );
  }
}

if( found ) {
  set_kb_item( name:"symfony/detected", value:TRUE );
  set_kb_item( name:"symfony/ssh-login/detected", value:TRUE );
  set_kb_item( name:"symfony/ssh-login/port", value:port );
}

exit( 0 );
