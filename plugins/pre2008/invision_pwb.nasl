# OpenVAS Vulnerability Test
# $Id: invision_pwb.nasl 11556 2018-09-22 15:37:40Z cfischer $
# Description: Invision Power Board XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_version("$Revision: 11556 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:37:40 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1578");
  script_bugtraq_id(11332);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Invision Power Board XSS");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");

  script_family("Web application abuses");

  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("invision_power_board/installed");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software");

  script_tag(name:"summary", value:"The remote host is running Invision Power Board, a web-based bulletin-board
system written in PHP.

This version of Invision Power Board is vulnerable to cross-site scripting attacks, which may allow an attacker to
steal users cookies.");

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
