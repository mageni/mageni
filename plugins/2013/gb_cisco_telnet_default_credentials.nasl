###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telnet_default_credentials.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Cisco Default Telnet Login
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103807");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-10-11 17:38:09 +0200 (Fri, 11 Oct 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("Cisco Default Telnet Login");
  script_category(ACT_ATTACK);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/cisco/ios/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"summary", value:"It was possible to login into the remote host using default credentials.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  script_timeout(600);

  exit(0);
}

include("telnet_func.inc");
include("default_credentials.inc");

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_default_account_checks" ) ) exit( 0 );

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );
if( "User Access Verification" >!< banner && "cisco" >!< banner )
  exit( 0 );

default = try( vendor:"cisco" );
if( ! default ) exit( 0 );

foreach pw( default ) {

  # nb: We don't need a special handling of ';' like in the other NVTs
  # using default_credentials.inc because the try above only returned
  # Cisco related credentials and is exiting if a user uploaded and
  # own credentials list.
  up = split( pw, sep:":", keep:FALSE );
  if( isnull( up[0] ) || isnull( up[1] ) ) continue;

  soc = open_sock_tcp( port );
  if( ! soc ) continue;

  user = up[0];
  pass = up[1];

  if( tolower( pass ) == "none" ) pass = "";

  send( socket:soc, data:user + '\r\n' );
  ret = recv( socket:soc, length:1024 );

  if( "ass" >!< ret ) {
    close( soc );
    sleep( 1 );
    continue;
  }

  send( socket:soc, data:pass + '\r\n' );
  ret = recv( socket:soc, length:1024 );

  send(socket:soc, data:'show ver\r\n');

  ret = recv( socket:soc, length:4096 );
  close( soc );

  if( "Cisco IOS Software" >< ret || "Cisco Internetwork Operating System Software" >< ret ) {
    report = 'It was possible to login as user "' + user + '" with password "' + pass + '".\n'; ;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );