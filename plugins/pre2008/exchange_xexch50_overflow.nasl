# OpenVAS Vulnerability Test
# $Id: exchange_xexch50_overflow.nasl 13137 2019-01-18 07:33:34Z cfischer $
# Description: Exchange XEXCH50 Remote Buffer Overflow
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
# Improved by John Lampe to see if XEXCH is an allowed verb
#
# Copyright:
# Copyright (C) 2003 Digital Defense Inc.
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

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11889");
  script_version("$Revision: 13137 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 08:33:34 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(8838);
  script_cve_id("CVE-2003-0714");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Exchange XEXCH50 Remote Buffer Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Digital Defense Inc.");
  script_family("SMTP problems");
  script_dependencies("sw_ms_exchange_server_remote_detect.nasl");
  script_mandatory_keys("microsoft/exchange_server/smtp/detected");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS03-046.mspx");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This system appears to be running a version of the Microsoft Exchange
  SMTP service that is vulnerable to a flaw in the XEXCH50 extended verb.");

  script_tag(name:"impact", value:"This flaw can be used to completely crash Exchange 5.5 as well as execute
  arbitrary code on Exchange 2000.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"smtp"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port))
  exit(0);

if(smtp_get_is_marked_wrapped(port:port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

greeting = smtp_recv_banner(socket:soc);
if(!egrep(string:greeting, pattern:"microsoft", icase:TRUE))
  exit(0);

send(socket:soc, data:string("EHLO X\r\n"));
ok = smtp_recv_line(socket:soc);
if(!ok || "XEXCH50" >!< ok) {
  smtp_close(socket:soc, check_data:ok);
  exit(0);
}

send(socket:soc, data:string("MAIL FROM: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if(!ok) {
  smtp_close(socket:soc, check_data:ok);
  exit(0);
}

send(socket:soc, data:string("RCPT TO: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if(!ok) {
  smtp_close(socket:soc, check_data:ok);
  exit(0);
}

send(socket:soc, data:string("XEXCH50 2 2\r\n"));
ok = smtp_recv_line(socket:soc);
smtp_close(socket:soc, check_data:ok);
if(!ok)
  exit(0);

if(egrep(string:ok, pattern:"^354 Send binary")) {
  security_message(port:port);
  exit(0);
}

exit(99);