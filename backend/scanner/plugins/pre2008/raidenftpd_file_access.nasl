# OpenVAS Vulnerability Test
# $Id: raidenftpd_file_access.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: RaidenFTPD Unauthorized File Access flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

#  Ref: Lachlan. H

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18225");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1480");
  script_bugtraq_id(13292);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RaidenFTPD Unauthorized File Access flaw");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/login");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/raidenftpd/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to 2.4 build 2241 or newer.");

  script_tag(name:"summary", value:"The remote host is running the RaidenFTPD FTP server.

  The remote version of this software is vulnerable to a directory
  traversal flaw.");

  script_tag(name:"impact", value:"A malicious user could exploit it to obtain read
  access to the outside of the intended ftp root.");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];
if ( ! login || ! password )
  exit(0);

banner = get_ftp_banner(port: port);
if(!banner || !egrep(pattern:".*RaidenFTPD.*", string:banner))
  exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  ftp_recv_line(socket:soc);
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
    s = string("quote site urlget file:/..\\boot.ini\r\n");
    send(socket:soc, data:s);
    r = ftp_recv_line(socket:soc);
    if ("220 site urlget " >< r)
      security_message(port);
  }
  close(soc);
}