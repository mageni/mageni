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
  script_oid("1.3.6.1.4.1.25623.1.0.117305");
  script_version("2021-04-12T06:17:44+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-12 10:16:30 +0000 (Mon, 12 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-12 06:07:57 +0000 (Mon, 12 Apr 2021)");
  script_name("VyOS Default Credentials (SSH)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://support.vyos.io/en/kb/articles/default-user-password-for-vyos-2");

  script_tag(name:"summary", value:"The remote VyOS system is using known default credentials for
  the SSH login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Tries to login using the default credentials: 'vyos:vyos'.");

  script_tag(name:"affected", value:"All VyOS systems using known default credentials.");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

username = "vyos";
password = "vyos";

port = ssh_get_port( default:22 );

banner = ssh_get_serverbanner( port:port );
if( ! banner )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

login = ssh_login( socket:soc, login:username, password:password, priv:NULL, passphrase:NULL );
if( login == 0 ) {

  files = traversal_files( "linux" );

  foreach pattern( keys( files ) ) {

    file = "/" + files[pattern];

    cmd = ssh_cmd( socket:soc, cmd:"cat " + file );

    if( egrep( string:cmd, pattern:pattern, icase:TRUE ) ) {
      if( soc )
        close( soc );

      report = 'It was possible to login to the remote VyOS system via SSH with the following known credentials:\n';
      report += '\nUsername: "' + username  + '", Password: "' + password + '"\n';
      report += 'and to execute `cat ' + file + '`. Result:\n\n' + cmd;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

if( soc )
  close( soc );

exit( 99 );