###############################################################################
# OpenVAS Vulnerability Test
# $Id: ldu_801.nasl 11727 2018-10-02 13:45:55Z cfischer $
#
# Description: Land Down Under <= 801 Multiple Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at ramat doti cc>
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
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
###############################################################################

CPE = "cpe:/a:neocrome:land_down_under";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19603");
  script_version("$Revision: 11727 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-02 15:45:55 +0200 (Tue, 02 Oct 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2788", "CVE-2005-2884");
  script_bugtraq_id(14685, 14746, 14820);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Land Down Under <= 801 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_dependencies("ldu_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ldu/detected");

  script_xref(name:"URL", value:"http://securityfocus.com/archive/1/409511");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0509-advisories/LDU801.txt");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"summary", value:"The remote version of Land Down Under is prone to several SQL injection
  and cross-site scripting attacks due to its failure to sanitize
  user-supplied input to several parameters used by the 'events.php',
  'index.php', and 'list.php' scripts. A malicious user can exploit
  exploit these flaws to manipulate SQL queries, steal authentication
  cookies, and the like.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/list.php?c='&s=title&w=asc&o=vuln-test&p=1";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if ("MySQL error" >< res && egrep(string:res, pattern:"syntax to use near '(asc&o=|0.+page_vuln-test)")) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);