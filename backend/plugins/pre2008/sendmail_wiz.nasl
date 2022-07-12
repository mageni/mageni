# OpenVAS Vulnerability Test
# $Id: sendmail_wiz.nasl 13204 2019-01-21 17:32:45Z cfischer $
# Description: Sendmail WIZ
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16024");
  script_version("$Revision: 13204 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 18:32:45 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2897);
  script_cve_id("CVE-1999-0145");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Sendmail WIZ");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Michel Arboi");
  script_family("SMTP problems");
  script_dependencies("gb_sendmail_detect.nasl");
  script_mandatory_keys("sendmail/detected");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"Your MTA accepts the WIZ command. It must be a very old version
  of Sendmail.");

  script_tag(name:"insight", value:"WIZ allows remote users to execute arbitrary commands as root
  without the need to log in.");

  script_tag(name:"solution", value:"Reconfigure or upgrade your MTA.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"smtp"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

res = smtp_recv_banner(socket:soc);
if(!res || "endmail" >!< res) {
  smtp_close(socket:soc, check_data:res);
  exit(0);
}

# nb: We could also test the "KILL" function, which is related to WIZ if I understood correctly
req = string("WIZ\r\n");
send(socket:soc, data:req);
res = smtp_recv_line(socket:soc, code:"2[0-9]{2}");
smtp_close(socket:soc, check_data:res);

if(ereg(string:res, pattern:"^2[0-9]{2}[- ].+")) {
  report = 'The remote SMTP service accepts the WIZ command. Answer:\n\n' + res;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);