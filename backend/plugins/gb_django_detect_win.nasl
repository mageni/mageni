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
  script_oid("1.3.6.1.4.1.25623.1.0.113345");
  script_version("2019-04-25T11:36:15+0000");
  script_tag(name:"last_modification", value:"2019-04-25 11:36:15 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-27 10:15:22 +0100 (Wed, 27 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Django Version Detection (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_manage_engine_opmanager_consolidation.nasl", "toolcheck.nasl",
  "smb_login.nasl", "smb_nativelanman.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("manageengine/opmanager/detected", "SMB/login",
  "SMB/password", "Tools/Present/wmi");
  script_exclude_keys("SMB/samba");

  script_tag(name:"summary", value:"This script detects the installed version of Django
  and sets the result in KB.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/");

  exit(0);
}

CPE = "cpe:/a:django_project:django:";

include( "host_details.inc" );
include( "smb_nt.inc" );
include( "cpe.inc" );

if( ! defined_func( "win_cmd_exec" ) ) exit( 0 );
if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) ) exit( 0 );
if( kb_smb_is_samba() ) exit( 0 );

port = kb_smb_transport();
if( ! port ) port = 139;
if( ! get_port_state( port ) ) exit( 0 );

username = kb_smb_login();
password = kb_smb_password();
if( ! username && ! password ) exit( 0 );

function run_command( command ) {

  local_var command, serQueryRes;

  serQueryRes = win_cmd_exec( cmd: command, password: password, username: username );

  if( "Access is denied" >< serQueryRes ) {
    return;
  } else if( "The specified service does not exist" >< serQueryRes ) {
    return;
  } else if( "The service cannot be started" >< serQueryRes && "it is disabled" >< serQueryRes ) {
    return;
  } else if( "OpenService FAILED" >< serQueryRes && "specified service does not exist" >< serQueryRes ) {
    return;
  } else if( "StartService FAILED" >< serQueryRes ) {
    return;
  } else if( "An instance of the service is already running" >< serQueryRes ) {
    return;
  } else {
    return serQueryRes;
  }
}

domain = kb_smb_domain();
if( domain ) username = domain + "/" + username;

cmd = "cmd /c django-admin --version";
result = run_command( command: cmd );
if( isnull( result ) ) exit( 0 );
if( result =~ 'not recognized' || result =~ 'not found' ) exit( 0 );
ver = eregmatch( string: result, pattern: '\n([0-9.]+)' );
if( isnull( ver[1] ) ) exit( 0 );
set_kb_item( name: "django/windows/detected", value: TRUE );
register_and_report_cpe( app: 'Django',
                         ver: ver[1],
                         concluded: ver[0],
                         base: CPE,
                         expr: '([0-9.]+)',
                         regService: 'smb-login' );
exit( 0 );
