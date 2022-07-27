###############################################################################
# OpenVAS Vulnerability Test
# $Id: nortel_passport_default_pass.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Nortel/Bay Networks default password
#
# Authors:
# Rui Bernardino <rbernardino@oni.pt>
#
# Copyright:
# Copyright (C) 2002 Rui Bernardino
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
  script_oid("1.3.6.1.4.1.25623.1.0.10989");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Nortel/Bay Networks default password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Rui Bernardino");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/nortel_bay_networks/device/detected");

  script_tag(name:"solution", value:"Telnet this switch/router and change all passwords
  (check the manual for default users)");

  script_tag(name:"summary", value:"The remote switch/routers uses the default password.
  This means that anyone who has (downloaded) a user manual can
  telnet to it and gain administrative access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );

banner = get_telnet_banner( port:port );
if( ! banner || "Passport" >!< banner || "NetLogin:" >!< banner )
  exit( 0 );

# Although there are at least 11 (!?) default passwords to check, the passport will only allow
# 3 attempts before closing down the telnet port for 60 seconds. Fortunatelly, nothing prevents
# you to establish a new connection for each password attempt and then close it before the 3 attempts.

creds = make_array(
"rwa", "rwa",
"rw", "rw",
"l3", "l3",
"l2", "l2",
"ro", "ro",
"l1", "l1",
"l4admin", "l4admin",
"slbadmin", "slbadmin",
"operator", "operator",
"l4oper", "l4oper",
"slbop", "slbop" );

report = 'The following default credentials where identified: (user:pass)\n';

foreach cred( keys( creds ) ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  buf = telnet_negotiate( socket:soc );

  if( "NetLogin:" >< buf ) {
    close( soc );
    exit( 0 );
  }

  if( "Passport" >< buf && "Login:" >< buf ) {
    test = string( cred, "\n", creds[cred], "\n" );
    send( socket:soc, data:test );
    resp = recv( socket:soc, length:1024 );

    if( "Access failure" >< resp ) {
      close( soc );
      break;
    }

    if( ! ( "Login" >< resp ) ) {
      VULN = TRUE;
      report += '\n' + cred + ":" + creds[cred];
    }
  } else {
    close( soc );
    break;
  }
  close( soc );
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );