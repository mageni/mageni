# OpenVAS Vulnerability Test
# Description: Invision Power Board XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15425");
  script_version("2022-05-31T14:18:25+0000");
  script_tag(name:"last_modification", value:"2022-06-01 10:00:47 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11332");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Invision Power Board XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2005 David Maciejak");

  script_family("Web application abuses");

  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("invision_power_board/installed");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software");

  script_tag(name:"summary", value:"Invision Power Board is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"This version of Invision Power Board is vulnerable to XSS, which
  may allow an attacker to steal users cookies.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

s = string( "GET ", dir, "/index.php?s=5875d919a790a7c429c955e4d65b5d54&act=Login&CODE=00 HTTP/1.1\r\n", "Host: ",
            get_host_name(), "\r\n", "Referer: <script>foo</script>", "\r\n\r\n");
soc =  http_open_socket(port);
if(!soc) exit(0);

send(socket: soc, data: s);
r = http_recv(socket: soc);
http_close_socket(soc);

if (r =~ "HTTP/1\.. 200" && egrep(pattern:"input type=.*name=.referer.*<script>foo</script>", string:r) )
{
  security_message(port);
  exit(0);
}

exit(99);
