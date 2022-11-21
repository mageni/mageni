# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108157");
  script_version("2022-11-15T07:43:20+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-11-15 07:43:20 +0000 (Tue, 15 Nov 2022)");
  script_tag(name:"creation_date", value:"2017-05-10 09:37:58 +0200 (Wed, 10 May 2017)");
  script_name("Read Asset Identification Tag on scanned host (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");

  script_add_preference(name:"Enable", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"This routine reads the Greenbone Asset Identifier of a
  system, provided it is a unixoid system offering SSH access.

  By default, this routine is disabled even it is selected to run. To activate it, it needs to be
  explicitly enabled with its corresponding preference switch.

  The file is named asset.id and found within the directory /etc/greenbone/.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("host_details.inc");

SCRIPT_DESC = "Read Asset Identification Tag on scanned host (Linux/Unix SSH Login)";

enabled = script_get_preference( "Enable", id:1 );
if( "yes" >!< enabled )
  exit( 0 );

if( get_kb_item( "ssh/no_linux_shell" ) ) {
  log_message( port:0, data:"Target system does not offer a standard shell. Can not continue." );
  exit( 0 );
}

if( ! soc = ssh_login_or_reuse_connection() )
  exit( 0 );

file = "asset.id";
path = "/etc/greenbone/";
path_file = path + file;

cmd = "ls -d " + path;
dir_exist = ssh_cmd( socket:soc, cmd:cmd, return_linux_errors_only:TRUE );
if( ! dir_exist ) {
  log_message( port:0, data:"Empty response received for command '" + cmd + "'" );
  ssh_close_connection();
  exit( 0 );
}

if( dir_exist =~ "no such file" ) {
  log_message( port:0, data:"Directory '" + path + "' does not exist. Can not continue." );
  ssh_close_connection();
  exit( 0 );
}

cmd = "ls -l " + path_file;
file_exist = ssh_cmd( socket:soc, cmd:cmd, return_linux_errors_only:TRUE );
if( ! file_exist ) {
  log_message( port:0, data:"Empty response received for command '" + cmd + "'. Can not continue." );
  ssh_close_connection();
  exit( 0 );
}

if( file_exist =~ "permission denied" ) {
  log_message( port:0, data:"Permission denied while accessing file '" + path_file  +  "'. Can not continue." );
  ssh_close_connection();
  exit( 0 );
}

if( file_exist !~ "no such file" ) {

  cmd = "cat " + path_file;
  current_content = ssh_cmd( socket:soc, cmd:cmd, return_linux_errors_only:TRUE );
  if( ! current_content ) {
    log_message( port:0, data:"Empty response received for command '" + cmd + "'. Can not continue." );
    ssh_close_connection();
    exit( 0 );
  }

  asset_id = eregmatch( pattern:"^[0-9.]+,([0-9a-f-]+)", string:current_content );
  if( asset_id[1] ) {
    register_host_detail( name:"Greenbone-Asset-ID", value:asset_id[1], desc:SCRIPT_DESC );
    log_message( port:0, data:"Greenbone Asset ID tag '" + asset_id[1] + "' successfully collected from '" + path_file  + "'." );
  } else {
    log_message( port:0, data:"Failed to collect Greenbone Asset ID tag from '" + path_file  + "' (Possible malformed/invalid file). Received response: " + current_content );
  }
} else {
  log_message( port:0, data:"Greenbone Asset ID file '" + path_file  + "' does not exist. Can not continue." );
}

ssh_close_connection();

exit( 0 );
