###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_ssh_version.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# Cisco Wireless LAN Controller Detection (SSH)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105429");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13568 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-30 14:08:04 +0100 (Fri, 30 Oct 2015)");
  script_name("Cisco Wireless LAN Controller Detection (SSH)");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco Wireless LAN Controller");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

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

if( ! user || ! pass ) exit( 0 );

for( i=0; i < 3; i++ )
{
  soc = open_sock_tcp( port );

  sess = ssh_connect( socket:soc );

  if( ! sess ) exit( 0 );

  if( ssh_userauth( sess, login:FALSE, password:FALSE, privatekey:FALSE, passphrase:FALSE ) ) exit( 0 );

  shell = ssh_shell_open( sess );
  if( ! shell ) exit( 0 );

  buf = ssh_read_from_shell( sess:sess, pattern:"User:", timeout:30, retry:10 );

  if( "User" >!< buf ) continue;

  ssh_shell_write( sess, cmd:user + '\n' + pass + '\n' + 'show sysinfo\n\nshow inventory\n');

  buf = ssh_read_from_shell( sess:sess, pattern:"PID", timeout:30, retry:10 );

  close( soc );

  if( buf !~ 'Product Name.*Cisco Controller' ) exit( 0 );

  set_kb_item( name:"cisco_wlc/detected", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );

  version = eregmatch( pattern:'Product Version[.]+ ([0-9][^\r\n ]+)', string:buf );
  if( ! isnull( version[1] ) ) set_kb_item( name:"cisco_wlc/version/ssh", value:version[1] );


  model = eregmatch(string:buf, pattern:"PID: ([^,]+),");
  if( ! isnull( model[1] ) ) set_kb_item( name:"cisco_wlc/model/ssh", value:model[1] );

  set_kb_item( name:"cisco_wlc/sysinfo", value:buf );

  exit( 0 );

}

exit( 0 );