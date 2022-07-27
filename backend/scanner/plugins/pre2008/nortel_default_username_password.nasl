###############################################################################
# OpenVAS Vulnerability Test
# $Id: nortel_default_username_password.nasl 13571 2019-02-11 11:00:12Z cfischer $
#
# Nortel Default Username and Password
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.15715");
  script_version("$Revision: 13571 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 12:00:12 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Nortel Default Username and Password");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"solution", value:"Set a strong password for the account.");

  script_tag(name:"summary", value:"The username/password combination 'ro/ro' or 'rwa/rwa' are valid.

  These username and password are the default ones for many of
  Nortel's network devices.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("ssh_func.inc");

port = get_ssh_port( default:22 );

# Exit if any random user/pass pair is accepted by the SSH service.
if( ssh_broken_random_login( port:port ) ) exit( 0 );

creds = make_array(
"ro", "ro",
"rwa", "rwa" );

report = 'The following default credentials where identified: (user:pass)\n';

foreach cred( keys( creds ) ) {
  soc = open_sock_tcp( port );
  if ( ! soc ) exit( 0 );
  ret = ssh_login( socket:soc, login:cred, password:creds[cred] );
  close( soc );
  if( ret == 0 ) {
    VULN = TRUE;
    report += '\n' + cred + ":" + creds[cred];
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );