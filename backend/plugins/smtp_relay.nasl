###############################################################################
# OpenVAS Vulnerability Test
# $Id: smtp_relay.nasl 13470 2019-02-05 12:39:51Z cfischer $
#
# SMTP Open Relay Test
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100073");
  script_version("$Revision: 13470 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 13:39:51 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-23 19:32:33 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-0512", "CVE-2002-1278", "CVE-2003-0285");
  script_name("Mail relaying");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("smtpserver_detect.nasl", "smtp_settings.nasl", "global_settings.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);
  script_mandatory_keys("smtp/banner/available");
  script_exclude_keys("keys/is_private_addr", "keys/islocalhost", "keys/islocalnet");

  script_tag(name:"solution", value:"Improve the configuration of your SMTP server so that your SMTP server
  cannot be used as a relay any more.");

  script_tag(name:"summary", value:"The remote SMTP server is insufficiently protected against mail relaying.");

  script_tag(name:"impact", value:"This means that spammers might be able to use your mail server
  to send their mails to the world.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("network_func.inc");

if(islocalhost())
  exit(0);

if(islocalnet())
  exit(0);

if(is_private_addr())
  exit(0);

domain = get_3rdparty_domain();
src_name = this_host_name();
vtstrings = get_vt_strings();
FROM = string(vtstrings["lowercase"], '@', src_name);
TO = string(vtstrings["lowercase"], '@', domain);

port = get_smtp_port(default:25);
if(get_kb_item("smtp/" + port + "/qmail/detected"))
  exit(0);

if(smtp_get_is_marked_wrapped(port:port))
  exit(0);

helo_name = smtp_get_helo_from_kb(port:port);
soc = smtp_open(port:port, data:helo_name, send_helo:TRUE, code:"250");
if(!soc)
  exit(0);

mf = strcat('MAIL FROM: <', FROM , '>\r\n');
send(socket:soc, data:mf);
l = smtp_recv_line(socket:soc);
if(!l || l =~ '^5[0-9]{2}') {
  smtp_close(socket:soc, check_data:l);
  exit(0);
}
mfres = l;

rt = strcat('RCPT TO: <', TO , '>\r\n');
send(socket:soc, data:rt);
l = smtp_recv_line(socket:soc, code:"2[0-9]{2}");
if(!l) {
  smtp_close(socket:soc, check_data:l);
  exit(0);
}
rtres = l;

data = string("data\r\n");
send(socket: soc, data: data);
l = smtp_recv_line(socket:soc, code:"3[0-9]{2}");
if(!l) {
  smtp_close(socket:soc, check_data:l);
  exit(0);
}
datares = l;

dc = string(vtstrings["default"], "-Relay-Test\r\n.\r\n");
send(socket:soc, data:dc);
l = smtp_recv_line(socket:soc, code:"250");
smtp_close(socket:soc, check_data:l);

if(l) {
  report  = 'The scanner was able to relay mails by sending those sequences:\n\n';
  report += 'Request: ' + chomp( mf );
  report += '\nAnswer:  ' + chomp( mfres );
  report += '\nRequest: ' + chomp( rt );
  report += '\nAnswer:  ' + chomp( rtres );
  report += '\nRequest: ' + chomp( data );
  report += '\nAnswer:  ' + chomp( datares );
  report += '\nRequest: ' + chomp( dc );
  report += '\nAnswer:  ' + chomp( l );
  security_message(port:port, data:report);
  set_kb_item(name:"smtp/" + port + "/spam", value:TRUE);
  set_kb_item(name:"smtp/spam", value:TRUE);
  exit(0);
}

exit(99);