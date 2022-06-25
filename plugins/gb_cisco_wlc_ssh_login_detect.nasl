# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105429");
  script_version("2021-06-11T11:28:00+0000");
  script_tag(name:"last_modification", value:"2021-06-14 10:28:51 +0000 (Mon, 14 Jun 2021)");
  script_tag(name:"creation_date", value:"2015-10-30 14:08:04 +0100 (Fri, 30 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco Wireless LAN Controller (WLC) Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available", "Secret/SSH/login", "Secret/SSH/password");

  script_tag(name:"summary", value:"SSH login-based detection of Cisco Wireless LAN Controller (WLC).");

  exit(0);
}

include("ssh_func.inc");

if( ! defined_func( "ssh_shell_open" ) )
  exit( 0 );

port = kb_ssh_transport();
if( ! get_port_state( port ) )
  exit( 0 );

user = kb_ssh_login();
pass = kb_ssh_password();

if( ! user || ! pass )
  exit( 0 );

for( i = 0; i < 3; i++ ) {

  if( ! soc = open_sock_tcp( port ) )
    continue;

  sess = ssh_connect( socket:soc );
  if( ! sess ) {
    close( soc );
    continue;
  }

  if( ssh_userauth( sess, login:NULL, password:NULL, privatekey:NULL, passphrase:NULL ) ) {
    close( soc );
    continue;
  }

  shell = ssh_shell_open( sess );
  if( ! shell ) {
    close( soc );
    continue;
  }

  buf = ssh_read_from_shell( sess:sess, pattern:"User:", timeout:30, retry:10 );
  if( ! buf || "User" >!< buf ) {
    close( soc );
    continue;
  }

  ssh_shell_write( sess, cmd:user + '\n' + pass + '\n' + 'show sysinfo\n\nshow inventory\n' );

  buf = ssh_read_from_shell( sess:sess, pattern:"PID", timeout:30, retry:10 );

  close( soc );

  if( ! buf || buf !~ "Product Name.*Cisco Controller" )
    exit( 0 );

  set_kb_item( name:"cisco/wlc/detected", value:TRUE );
  set_kb_item( name:"cisco/wlc/ssh-login/detected", value:TRUE );
  set_kb_item( name:"cisco/wlc/ssh-login/port", value:port );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );

  version = "unknown";

  vers = eregmatch( pattern:'Product Version[.]+ ([0-9][^\r\n ]+)', string:buf );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  mod = eregmatch( string:buf, pattern:"PID: ([^,]+)," );
  if( ! isnull( mod[1] ) )
    model = mod[1];

  set_kb_item( name:"cisco/wlc/ssh-login/" + port + "/concluded", value:buf );
  set_kb_item( name:"cisco/wlc/ssh-login/" + port + "/version", value:version );
  set_kb_item( name:"cisco/wlc/ssh-login/" + port + "/model", value:model );

  exit( 0 );
}

exit( 0 );