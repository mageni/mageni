###############################################################################
# OpenVAS Vulnerability Test
# $Id: 3com_switches.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# 3Com Superstack 3 switch with default password
#
# Authors:
# Patrik Karlsson <patrik.karlsson@ixsecurity.com>
# Enhancements by Tomi Hanninen
#
# Copyright:
# Copyright (C) 2001 Patrik Karlsson
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
  script_oid("1.3.6.1.4.1.25623.1.0.10747");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("3Com Superstack 3 switch with default password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 Patrik Karlsson");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports(23); # the port can't be changed on the device
  script_mandatory_keys("telnet/banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_add_preference(name:"Use complete password list (not only vendor specific passwords)", type:"checkbox", value:"no");

  script_tag(name:"solution", value:"Telnet to this switch and change the default passwords
  immediately.");

  script_tag(name:"summary", value:"The 3Com Superstack 3 switch has the default passwords set.");

  script_tag(name:"impact", value:"The attacker could use these default passwords to gain remote
  access to your switch and then reconfigure the switch. These passwords could
  also be potentially used to gain sensitive information about your network from the switch.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");
include("default_credentials.inc");

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_default_account_checks" ) ) exit( 0 );

port = 23; # the port can't be changed on the device
if( ! get_port_state( port ) ) exit( 0 );
banner = get_telnet_banner( port:port );
if( !banner || "Login : " >!< banner ) exit( 0 );

p = script_get_preference( "Use complete password list (not only vendor specific passwords)" );
if( "yes" >< p ) {
  clist = try();
} else {
  clist = try( vendor:"3com" );
}
if( ! clist ) exit( 0 );

found = FALSE;

report = string( "Standard passwords were found on this 3Com Superstack switch.\n" );
report += string( "The passwords found are:\n\n" );

foreach credential( clist ) {

  # Handling of user uploaded credentials which requires to escape a ';' or ':'
  # in the user/password so it doesn't interfere with our splitting below.
  credential = str_replace( string:credential, find:"\;", replace:"#sem_legacy#" );
  credential = str_replace( string:credential, find:"\:", replace:"#sem_new#" );

  user_pass = split( credential, sep:":", keep:FALSE );
  if( isnull( user_pass[0] ) || isnull( user_pass[1] ) ) {
    # nb: ';' was used pre r9566 but was changed to ':' as a separator as the
    # GSA is stripping ';' from the NVT description. Keeping both in here
    # for backwards compatibility with older scan configs.
    user_pass = split( credential, sep:";", keep:FALSE );
    if( isnull( user_pass[0] ) || isnull( user_pass[1] ) )
      continue;
  }

  user = chomp( user_pass[0] );
  pass = chomp( user_pass[1] );

  user = str_replace( string:user, find:"#sem_legacy#", replace:";" );
  pass = str_replace( string:pass, find:"#sem_legacy#", replace:";" );
  user = str_replace( string:user, find:"#sem_new#", replace:":" );
  pass = str_replace( string:pass, find:"#sem_new#", replace:":" );

  if( tolower( pass ) == "none" ) pass = "";

  soc = open_sock_tcp( port );
  if( ! soc ) continue;

  r = recv( socket:soc, length:160 );
  if( "Login: " >< r ) {
    tmp = string( user, "\r\n" );
    send( socket:soc, data:tmp );
    r = recv_line( socket:soc, length:2048 );
    tmp = string( pass, "\r\n" );
    send( socket:soc, data:tmp );
    r = recv( socket:soc, length:4096 );

    if( "logout" >< r ) {
      found = TRUE;
      report += string( user, ":", pass, "\n" );
    }
  }
  close( soc );
}

if( found ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );