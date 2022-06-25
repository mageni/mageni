# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108946");
  script_version("2020-10-19T10:50:01+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 10:21:19 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-19 10:28:09 +0000 (Mon, 19 Oct 2020)");
  script_name("ZeroShell Default Credentials (SSH)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/openssh/detected"); # nb: Versions 1.0 up to 3.9 are using OpenSSH
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://zeroshell.org/faq/generic/");

  script_tag(name:"summary", value:"The remote ZeroShell system is using known default credentials for the SSH-Login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Tries to login using the default credentials: 'admin:zeroshell'.");

  script_tag(name:"affected", value:"All ZeroShell systems using known default credentials.");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("ssh_func.inc");
include("port_service_func.inc");
include("host_details.inc");

creds = make_list( "admin:zeroshell" );
pattern = "(Z e r o S h e l l|Z E R O S H E L L|COMMAND MENU)";
report = 'It was possible to login to the remote ZeroShell system via SSH with the following known credentials:\n';

port = ssh_get_port( default:22 );

banner = ssh_get_serverbanner( port:port );
if( ! banner || "OpenSSH" >!< banner )
  exit( 0 );

foreach cred( creds ) {

  if( ! soc = open_sock_tcp( port ) )
    continue;

  split = split( cred, sep:":", keep:FALSE );
  if( max_index( split ) != 2 )
    continue;

  username = split[0];
  password = split[1];

  login = ssh_login( socket:soc, login:username, password:password, priv:NULL, passphrase:NULL );
  if( login == 0 ) {

    cmd = ssh_cmd( socket:soc, cmd:"test" );

    if( match = egrep( pattern:pattern, string:cmd ) ) {
      vuln = TRUE;
      report += '\nUsername: "' + username  + '", Password: "' + password + '"';
      report += '\nProof:\n\n' + chomp( match );
    }
  }
  close( soc );
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
