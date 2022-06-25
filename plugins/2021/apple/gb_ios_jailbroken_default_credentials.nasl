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
  script_oid("1.3.6.1.4.1.25623.1.0.117505");
  script_version("2021-06-21T07:41:28+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-21 10:10:42 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-21 07:17:57 +0000 (Mon, 21 Jun 2021)");
  script_name("Apple iOS (Jailbroken) Default Credentials (SSH)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  # nb: Depending on the Jailbreak e.g. OpenSSH or Dropbear is getting installed according to
  # external sources. We only check these two as we don't want to run this VT against a wide range
  # of other SSH servers.
  script_mandatory_keys("ssh/openssh_or_dropbear/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.macworld.com/article/201053/iphone_password.html");
  script_xref(name:"URL", value:"https://blog.elcomsoft.com/2020/05/ios-jailbreaks-ssh-and-root-password/");

  script_tag(name:"summary", value:"The remote jailbroken Apple iOS device is using known default
  credentials for the SSH login.");

  script_tag(name:"vuldetect", value:"Tries to login via SSH using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"affected", value:"All jailbroken Apple iOS devices with default credentials.
  Other devices or vendors might be affected as well.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("ssh_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("os_func.inc");

port = ssh_get_port( default:22 );

banner = ssh_get_serverbanner( port:port );
if( ! banner || banner !~ "(OpenSSH|dropbear)" )
  exit( 0 );

creds = make_array();
creds["root"] = "alpine";
creds["mobile"] = "dottie";

report = 'It was possible to login with the following known default credentials:\n';

foreach username( keys( creds ) ) {

  if( ! soc = open_sock_tcp( port ) )
    continue;

  password = creds[username];

  login = ssh_login( socket:soc, login:username, password:password, priv:NULL, passphrase:NULL );
  if( login == 0 ) {

    files = traversal_files( "linux" );

    # From https://blog.elcomsoft.com/2020/05/ios-jailbreaks-ssh-and-root-password/.
    # nb: "Uppercase "R" is used here because the pattern already exists in traversal_files().
    files["(Root|admin|nobody):[^:]*:[0-9]+:(-2|[0-9]+):([^:]*:){2}"] = "private/etc/master.passwd";

    foreach pattern( keys( files ) ) {

      file = "/" + files[pattern];

      cmd = ssh_cmd( socket:soc, cmd:"cat " + file );

      if( egrep( string:cmd, pattern:pattern, icase:TRUE ) ) {
        VULN = TRUE;
        report += '\nUsername: "' + username  + '", Password: "' + password + '"\n';
        report += 'and to execute `cat ' + file + '`. Result (truncated):\n\n' + substr( cmd, 0, 100 );
        break;
      }
    }
  }
  close( soc );
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );