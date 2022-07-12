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
  script_oid("1.3.6.1.4.1.25623.1.0.117815");
  script_version("2021-12-09T08:03:40+0000");
  script_cve_id("CVE-2021-38759");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-12-09 11:40:32 +0000 (Thu, 09 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-09 07:53:21 +0000 (Thu, 09 Dec 2021)");
  script_name("Raspberry Pi OS / Raspbian Default Credentials (SSH)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  # nb: No mandatory key as there might be different SSH servers installed (OpenSSH, Dropbear, ...)
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.raspberrypi.com/documentation/computers/configuration.html#change-the-default-password");
  script_xref(name:"URL", value:"https://www.cnvd.org.cn/flaw/show/CNVD-2021-43968");

  script_tag(name:"summary", value:"The remote Raspberry Pi OS / Raspbian system is using known
  default credentials for the SSH login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Tries to login using the default credentials: 'pi:raspberry'.");

  script_tag(name:"affected", value:"All Raspberry Pi OS / Raspbian systems using known default
  credentials. Other systems might be affected as well.");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("os_func.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

username = "pi";
password = "raspberry";

login = ssh_login( socket:soc, login:username, password:password, priv:NULL, passphrase:NULL );
if( login == 0 ) {

  files = traversal_files( "linux" );

  foreach pattern( keys( files ) ) {

    file = "/" + files[pattern];

    cmd = ssh_cmd( socket:soc, cmd:"cat " + file );

    if( egrep( string:cmd, pattern:pattern, icase:TRUE ) ) {

      close( soc );

      report = 'It was possible to login to the remote Raspberry Pi OS / Raspbian system via SSH with the following known credentials:\n';
      report += '\nUsername: "' + username  + '", Password: "' + password + '"\n';
      report += 'and to execute `cat ' + file + '`. Result:\n\n' + cmd;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

close( soc );

exit( 99 );