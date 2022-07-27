# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108755");
  script_version("2020-04-22T12:21:03+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-23 10:03:00 +0000 (Thu, 23 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-22 10:00:04 +0000 (Wed, 22 Apr 2020)");
  script_name("Huawei VRP Default Credentials (SSH)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  # nb: Don't use the keys or dependencies to / from gb_huawei_vrp_network_device_consolidation.nasl / gb_huawei_vrp_network_device_ssh_banner_detect.nasl
  # because ssh_detect.nasl is checking for an additional banner which isn't necessarily a VRP device.
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/huawei/vrp/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1000060368/25506195/understanding-the-list-of-default-user-names-and-passwords");

  script_tag(name:"summary", value:"The remote Huawei Versatile Routing Platform (VRP) device is using
  known default credentials for the SSH-Login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The remote Huawei Versatile Routing Platform (VRP) device is lacking
  a proper password configuration, which makes critical information and actions accessible for people
  with knowledge of the default credentials.");

  script_tag(name:"vuldetect", value:"Tries to login using the default credentials: 'admin:admin',
  'root:admin' or 'admin:admin@huawei.com'.");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("ssh_func.inc");
include("misc_func.inc");

creds = make_list( "admin:admin@huawei.com",
                   "admin:admin",
                   "root:admin" );

cmd = "display version";

report = 'It was possible to login to the remote Huawei VRP device via SSH with the following known credentials:';

port = ssh_get_port( default:22 );

banner = ssh_get_serverbanner( port:port );
if( ! banner || ( banner != "SSH-2.0--" && "SSH-2.0-HUAWEI-" >!< banner ) )
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

    cmd_res = ssh_cmd( socket:soc, cmd:cmd, return_errors:FALSE, pty:TRUE, nosh:TRUE, clear_buffer:TRUE );
    ssh_disconnect( _last_libssh_sess );
    if( display_vers = egrep( pattern:"(Huawei Versatile Routing Platform|VRP \(R\) software)", string:cmd_res ) ) {
      vuln = TRUE;
      report += '\n\nUsername: "' + username  + '", Password: "' + password + '"';
      report += '\n\nIt was also possible to execute "' + cmd + '" as "' + username + '". Result:\n\n' + chomp( display_vers );
    }
  }
  close( soc );
  sleep( 5 ); # nb: The devices behaves "strange" with too many logins in a short amount of time.
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
