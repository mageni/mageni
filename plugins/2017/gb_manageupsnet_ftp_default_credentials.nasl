###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageupsnet_ftp_default_credentials.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# ManageUPSNET FTP Default Credentials
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113052");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-16 11:04:05 +0100 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("ManageUPSNET FTP Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/manageupsnet/detected");

  script_tag(name:"summary", value:"ManageUPSNET Telnet and FTP uses remote credentials 'admin' - 'admin'.");

  script_tag(name:"vuldetect", value:"The script tries to login via FTP using the username 'admin' and the password 'admin'.");

  script_tag(name:"impact", value:"Successful exploitation would allow to gain complete administrative access to the host.");

  script_tag(name:"affected", value:"All ManageUPSNET devices version 2.6 or later.");

  script_tag(name:"solution", value:"Change the default password for the administrative account 'admin' for both Telnet and FTP.");

  script_xref(name:"URL", value:"http://005c368.netsolhost.com/pdfs/9133161c.pdf");

  exit(0);
}

include( "ftp_func.inc" );

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );
if( !banner || "ManageUPSnet" >!< banner )
  exit( 0 );

login = "admin";
pass = "admin";

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

login_success = ftp_log_in(socket:soc, user:login, pass:pass);
if( login_success ) {
  VULN = TRUE;
  report = 'It was possible to login via FTP using the following default credentials:\n\n';
  report += 'Login: ' + login + ', Password: ' + pass;
}

close( soc );

if( VULN ) {
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );