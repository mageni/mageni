###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iprotect_default_ssh_credentials.nasl 13571 2019-02-11 11:00:12Z cfischer $
#
# iProtect Server Default SSH Login
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108306");
  script_version("$Revision: 13571 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 12:00:12 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-30 14:22:43 +0100 (Thu, 30 Nov 2017)");
  script_name("iProtect Server Default SSH Login");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("ssh/server_banner/available");

  script_xref(name:"URL", value:"http://www.keyprocessor.com/kennisbank/Zipfile/KP_iProtect_8_0.03%20Stand-by%20server_M_160523_EN");

  script_tag(name:"summary", value:"The remote iProtect server is prone to a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with known credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");

port = get_ssh_port( default:22 );

files = traversal_files("linux");

username = "atlas";
password = "kp4700";
report = 'It was possible to login to the remote iProtect server via SSH with the following credentials:\n';

if( ! soc = open_sock_tcp( port ) ) exit( 0 );
login = ssh_login( socket:soc, login:username, password:password, pub:NULL, priv:NULL, passphrase:NULL );

if( login == 0 ) {

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    cmd = ssh_cmd( socket:soc, cmd:"cat /" + file );

    if( passwd = egrep( pattern:pattern, string:cmd ) ) {
      vuln = TRUE;
      report += '\nUsername: "' + username  + '", Password: "' + password + '"';
      passwd_report += '\nIt was also possible to execute "cat /' + file + '" as "' + username + '". Result:\n\n' + passwd;
    }
  }
}

close( soc );

if( vuln ) {
  if( passwd_report ) report += '\n' + passwd_report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );