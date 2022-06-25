# OpenVAS Vulnerability Test
# $Id: translate_f.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: ASP/ASA source using Microsoft Translate f: bug
#
# Authors:
# Alexander Strouk
#
# Copyright:
# Copyright (C) 2000 Alexander Strouk
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
  script_oid("1.3.6.1.4.1.25623.1.0.10491");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1578);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0778");
  script_name("ASP/ASA source using Microsoft Translate f: bug");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Alexander Strouk");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Install all the latest Microsoft Security Patches (Note: This
  vulnerability is eliminated by installing Windows 2000 Service Pack 1)");

  script_tag(name:"summary", value:"There is a serious vulnerability in Windows 2000 (unpatched by SP1) that
  allows an attacker to view ASP/ASA source code instead of a processed file.

  ASP source code can contain sensitive information such as username's and
  passwords for ODBC connections.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
sig = get_http_banner( port:port );
if( ! sig || "IIS" >!< sig )
  exit(0);

host = http_host_name(port:port);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

url = "/global.asa\\";

req = string("GET ", url, " HTTP/1.0\r\n",
             "Host: ", host,"\r\n",
             "Translate: f\r\n\r\n");
send(socket:soc, data:req);
r = http_recv_headers2(socket:soc);
close(soc);

if(!r)
  exit(0);

if("Content-Type: application/octet-stream" >< r) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);