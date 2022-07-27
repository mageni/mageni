###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_audemat_fmb80_default_telnet_credentials.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Audemat FMB80 RDS Encoder Default root Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103898");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Audemat FMB80 RDS Encoder Default root Credentials");


  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2014/01/28/audemat-fmb80-rds-encoder-default-root-credentials/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-29 15:02:06 +0200 (Wed, 29 Jan 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  script_tag(name:"summary", value:"The remote Audemat FMB80 RDS Encoder has no or default credentials set.");
  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.");
  script_tag(name:"vuldetect", value:"Connect to the telnet service and, if needed, try to login with default credentials.");
  script_tag(name:"insight", value:"It was possible to login without credentials or default credentials of root:root.");
  script_tag(name:"solution", value:"Change/Set the password.");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = recv( socket:soc, length:2048 );
if( "FMB80" >!< recv ) exit( 0 );

if ( "User:" >< recv )
{
  pass_needed = TRUE;

  send( socket:soc, data:'root\r\n' );
  recv = recv( socket:soc, length:128 );
  if( "Password:" >!< recv ) exit( 0 );

  send( socket:soc, data:'root\r\n' );
  recv = recv( socket:soc, length:128 );
  if( "Type HELP" >!< recv ) exit( 99 );

}

send( socket:soc, data:'USER?\r\n' );
recv = recv( socket:soc, length:128 );

close( soc );

if( "Root" >< recv )
{
  if ( pass_needed )
    report = 'It was possible to login using the following credentials:\n\nroot:root\n';
  else
    report = 'The remote telnet service is not protected by any credentials.';

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
